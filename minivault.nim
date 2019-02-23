## Minivault
#
# Copyright 2019 Federico Ceratto <federico.ceratto@gmail.com>
# Released under GPLv3 License, see LICENSE file

import
  asyncdispatch,
  asynchttpserver,
  asyncnet,
  json,
  os,
  parseopt,
  posix,
  strutils,
  times

from sequtils import mapIt
from strformat import fmt

# TODO: statsd


onSignal(SIGABRT):
  ## Handle SIGABRT from systemd
  # Lines printed to stdout will be received by systemd and logged
  # Start with "<severity>" from 0 to 7
  echo "<2>Received SIGABRT"
  quit(1)

onSignal(SIGQUIT):
  echo "minivault exiting..."
  quit(1)

type
  InodeNotFoundError = object of Exception
  PidNotFoundError = object of Exception

const excluded_fd = {STDIN_FILENO.char, STDERR_FILENO.char,
                     STDOUT_FILENO.char}

proc find_pid(inode: int): Pid =
  #let t0 = epochTime()
  for q in walkPattern("/proc/*/fd/*"):
    if q[^2] == '/' and q[^1] in excluded_fd:
      continue

    var s:Stat
    discard stat(q, s)

    if s.st_ino.int != inode:
      continue

    try:
      result = q.split('/')[2].parseInt().Pid
    except ValueError:
      continue
    #echo "pid found in ", epochTime() - t0
    return

  # no PID found for incoming connection
  raise newException(PidNotFoundError, "")

proc find_inode(local_port, remote_port: Port): int =
  ## Find socket inode by port number
  # example      rem_port      lo_port
  #   14: 0100007F:8E10 0100007F:15D4 01
  const ipaddr_block = " 0100007F:"
  let
    hex_local_port = local_port.uint16.toHex()
    hex_remote_port = remote_port.uint16.toHex()
    matcher = ipaddr_block & hex_remote_port & ipaddr_block & hex_local_port & " 01 "

  for l in lines("/proc/net/tcp"):
    if l[4] != ':':
      continue  # not a connection line

    if l[5..36] == matcher:
      return l.splitWhitespace()[9].parseInt()

  raise newException(InodeNotFoundError, "")

type Status = object
  umask, state, groups: string
  tgid, ngid, pid, ppid, tracerpid, uid, gid: int
  nonewprivs, seccomp: int

proc read_status(pid: Pid): Status =
  ## Parse /proc/<pid>/status
  for l in lines("/proc/" & $pid & "/status"):
    if l.startswith("Umask:"):
      result.umask = l.splitWhitespace()[1]
    elif l.startswith("State:"):
      result.state = l.splitWhitespace(maxsplit=1)[1]
    elif l.startswith("Tgid:"):
      result.tgid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("Ngid:"):
      result.ngid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("PPid:"):
      result.ppid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("TracerPid:"):
      result.tracerpid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("Uid:"):
      result.uid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("Gid:"):
      result.gid = l.splitWhitespace()[1].parseInt()
    elif l.startswith("Groups:"):
      result.groups = l.splitWhitespace(maxsplit=1)[1]
    elif l.startswith("Seccomp:"):
      result.seccomp = l.splitWhitespace()[1].parseInt()
    elif l.startswith("NoNewPrivs:"):
      result.nonewprivs = l.splitWhitespace()[1].parseInt()

# globals :-/
var conf: JsonNode
var local_port = 5588.Port

proc handle_request(req: Request) {.async, gcsafe.} =
  ## Receive incoming connection
  let t0 = epochTime()
  let (remote_ipaddr, remote_port) = req.client.getPeerAddr()
  if remote_ipaddr != "127.0.0.1":
    echo "ERROR: request from " & remote_ipaddr
    await req.respond(Http403, "Forbidden")
    return

  if not req.url.path.startswith("/v1/"):
    echo "ERROR: unexpected path " & req.url.path
    await req.respond(Http403, "Forbidden")
    return

  try:
    let inode = find_inode(local_port, remote_port)
    let pid = find_pid(inode)
    let client_binpath = expandFilename("/proc/" & $pid & "/exe")
    let status = read_status(pid)

    let cred_name = req.url.path[4..^1]
    if not conf["credentials"].hasKey(cred_name):
      echo "no credential found"
      await req.respond(Http403, "Forbidden")
      return

    for k, v in conf["credentials"][cred_name].pairs:
      case k
      of "binpaths":
        if not v.mapIt(it.getStr()).contains(client_binpath):
          echo "executable not allowed: " & client_binpath
          await req.respond(Http403, "Forbidden")
          return
      of "uids":
        if not v.mapIt(it.getInt()).contains(status.uid):
          echo "UID not allowed: " & client_binpath
          await req.respond(Http403, "Forbidden")
          return
      of "gids":
        if not v.mapIt(it.getInt()).contains(status.gid):
          echo "GID not allowed: " & client_binpath
          await req.respond(Http403, "Forbidden")
          return

    echo fmt"serving {cred_name} to {client_binpath} UID {status.uid}"
    await req.respond(Http200, conf["credentials"][cred_name]["value"].getStr())

  except InodeNotFoundError:
    echo "error: inode not found"
    await req.respond(Http403, "Forbidden")
    return

  except PidNotFoundError:
    echo "error: no PID found for incoming connection"
    await req.respond(Http403, "Forbidden")
    return

  except Exception:
    echo "error: " & getCurrentExceptionMsg()
    await req.respond(Http403, "Forbidden")
    return


proc help() =
  echo """
Minivault

  -h         help
  -p:<port>  port number
  -c:<path>  conf file path [default: /etc/minivault.conf]
"""
  quit()

proc protect_memory() =
  if mlockall(MCL_CURRENT or MCL_FUTURE) == 0:
    return
  echo "unable to lock memory"
  quit(1)

proc main() =
  protect_memory()
  var conffile = "/etc/minivault.conf"
  for kind, key, val in getopt():
    case kind
    of cmdLongOption, cmdShortOption:
      case key
      of "help", "h":
        help()
      of "port", "p":
        local_port = val.parseInt().Port
      of "conf", "c":
        conffile = val
    of cmdArgument, cmdEnd: discard

  echo "minivault starting on port " & $(local_port.int)
  echo "config file: " & conffile
  conf = parseFile(conffile)
  if conf["format-version"].getInt() != 1:
    echo "wrong config format version"
    quit(1)
  if not conf.hasKey("credentials"):
    echo "missing credentials field"
    quit(1)
  var server = newAsyncHttpServer()
  waitFor server.serve(local_port, handle_request)

when isMainModule:
  main()
