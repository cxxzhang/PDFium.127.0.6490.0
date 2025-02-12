#!/usr/bin/env python3
# Copyright 2012 The Goma Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A tool to diagnose goma log file.

Usage)
  $ ./diagnose_goma_log.py
    - diagnose the latest goma logs

  $ ./diagnose_goma_log.py compiler_proxy.INFO
    - diagnose "compiler_proxy.INFO" file as goma log.

It shows
 - initial logs such as
      goma built revision
      goma flags
      goma version
 - Counts of each ReplyResponse
 - stats of duration of Task
 - Task log of ReplyResponse fail fallback
 - Error lines
 - Warning lines
"""



import datetime
import functools
import glob
import gzip
import json
import logging
import optparse
import os
import re
import sys


LOGLINE_RE = re.compile(
    '^([IWEF])(\\d{4,8} \\d{2}:\\d{2}:\\d{2}).(\\d{6})  *(.*)')


class TaskLog:
  """Log instances of a compile task."""

  def __init__(self, taskId, desc, start_time):
    self.id = taskId
    self.desc = desc
    self.compile_type = 'compile'
    if desc.startswith('precompiling '):
      self.compile_type = 'precompile'
    elif desc.startswith('linking '):
      self.compile_type = 'link'
    self.start_time = start_time
    self.end_time = start_time
    self.response = None
    self.loglines = []

  def Duration(self):
    """Task's duration.

    Returns:
      Task's duration in datetime.timedelta
    """
    return self.end_time - self.start_time


class LogLine:
  """A log instance."""

  def __init__(self, loglevel, time_str, micro_str, logtext):
    self.loglevel = loglevel
    self.logtext = logtext
    self._time_str = time_str
    self._micro_str = micro_str
    self._logtime = None  # invalid.

  def __str__(self):
    return '%s %s.%s %s' % (self.loglevel, self._time_str, self._micro_str,
                            self.logtext)
  @property
  def logtime(self):
    """Returns an instance of datetime.datetime when the log line is created."""
    if self._logtime:
      return self._logtime

    if not self._time_str or not self._micro_str:
      return None

    now = datetime.datetime.now()

    time_str = self._time_str
    if time_str[4] == ' ':
      # strptime won't accept "0229" if year is not provided.
      # c.f. http://bugs.python.org/issue26460
      time_str = str(now.year) + time_str
    lt = datetime.datetime.strptime(time_str, '%Y%m%d %H:%M:%S')
    if lt.month > now.month:
      lt.year -= 1
    self._logtime = datetime.datetime(
        lt.year, lt.month, lt.day, lt.hour, lt.minute, lt.second,
        int(self._micro_str))
    return self._logtime


class OpenWrapper:
  """A wrapper of open."""

  def __init__(self, filename):
    self._filename = filename
    self._fh = None

  def __enter__(self):
    _, ext = os.path.splitext(self._filename)
    if ext == '.gz':
      self._fh = gzip.open(self._filename, 'rt')
    else:
      self._fh = open(self._filename, 'rt')
    return self._fh

  def __exit__(self, unused_exc_type, unused_exc_value, unused_traceback):
    self._fh.close()


def ParseLogline(logline):
  """Parses a log line.

  Args:
    logline: a log line string
  Returns:
    a LogLine instance.  First line of log instance will have
    loglevel and logtext.  Followings will have None for these.
  """
  m = LOGLINE_RE.match(logline)
  if m:
    loglevel = m.group(1)
    logtext = m.group(4)
    return LogLine(loglevel, m.group(2), m.group(3), logtext)
  return LogLine(None, None, None, logline)


def FindCompilerProxyInfos(logdir):
  """Finds compiler_proxy INFO log files.

  Args:
    logdir: a log directory
  Returns:
    a list of full path names of compiler_proxy INFO log files of the last
    compiler_proxy invocation.
  """
  all_compiler_proxy_logs = glob.glob(
      os.path.join(logdir, 'compiler_proxy.*.INFO.*'))
  all_compiler_proxy_logs.sort(reverse=True)
  compiler_proxy_logs = []
  for logfile in all_compiler_proxy_logs:
    with OpenWrapper(logfile) as f:
      # Check if the file starts with "goma built revision" log.
      # It is the first log file of the compiler_proxy invocation.
      for line in f.readlines(1024):
        if line.find('goma built revision') > 0:
          compiler_proxy_logs.append(logfile)
          compiler_proxy_logs.reverse()
          return compiler_proxy_logs
      else:
        compiler_proxy_logs.append(logfile)
  all_compiler_proxy_logs.reverse()
  return all_compiler_proxy_logs


def IterLines(compiler_proxy_infos):
  """Generates each line in compiler_proxy_infos.

  Args:
    compiler_proxy_infos: a list of file names.
  Yields:
    a line string.
  """
  for logfile in compiler_proxy_infos:
    with OpenWrapper(logfile) as f:
      for line in f:
        yield line


def IterLoglines(lines):
  """Generates each LogLine from lines.

  Args:
    lines: a line generator
  Yields:
    a LogLine instance.
  """
  last_logline = None
  for line in lines:
    # logging.debug('line:%s' % line)
    logline = ParseLogline(line.rstrip())
    if not last_logline:
      last_logline = logline
      continue
    if logline.loglevel:
      yield last_logline
      last_logline = logline
      continue
    # drop "Log line format:" line.
    if logline.logtext.startswith('Log line format:'):
      continue
    last_logline.logtext += '\n' + logline.logtext
  yield last_logline


class DurationPerParallelism:
  """Duration per parallelism."""

  def __init__(self):
    self.durations = dict()
    self.last_time = None
    self.parallelism = 0

  def Start(self, time):
    """Start new task at the time."""
    self._Update(time)
    self.parallelism += 1

  def Finish(self, time):
    """Finish a task at the time."""
    self._Update(time)
    self.parallelism -= 1

  def _Update(self, time):
    duration = time - self.last_time
    if duration < datetime.timedelta():
      logging.debug('negative duration: %s - %s' % (time, self.last_time))
      duration = datetime.timedelta()
    self.durations.setdefault(self.parallelism, datetime.timedelta())
    self.durations[self.parallelism] += duration
    self.last_time = time


def ParseJsonStats(logline):
  """Parse json stats logged before compiler_proxy quitting.

  Args:
    logline: string (in json form)

  Returns:
    json object
  """
  try:
    return json.loads(logline)
  except ValueError as ex:
    print('failed to parse stats as json. stats=%s error=%s' % (logline, ex))
    return None


def LongValueFromJsonStats(json_stats, keys):
  """Get long integer value from stats with iterating keys.
  For example: when keys = ['stats', 'timeStats', 'uptime'], this returns
  long(json_stats['stats']['timeStats']['uptime']) if any.

  Args:
    stats: json
    keys: iterable keys

  Returns:
    long value if any. None otherwise.
  """
  curr = json_stats
  for k in keys:
    if not curr or k not in curr:
      return None
    curr = curr[k]
  if not curr:
    return None
  return int(curr)


class SimpleStats:
  """Simple Statistics."""

  def __init__(self):
    self.stats = {}

  def Update(self, name, value):
    """Update statistics.

    Args:
      name: a string name of entry.
      value: a numeric value to add.
    """
    if not self.stats.get(name):
      self.stats[name] = {}
    self.stats[name]['num'] = self.stats[name].get('num', 0) + 1
    self.stats[name]['min'] = min(
        self.stats[name].get('min', sys.maxsize), value)
    self.stats[name]['max'] = max(
        self.stats[name].get('max', -sys.maxsize - 1), value)
    self.stats[name]['sum'] = self.stats[name].get('sum', 0) + value
    self.stats[name]['sum_x2'] = (
        self.stats[name].get('sum_x2', 0) + value*value)


def DiagnoseGomaLog(options, args):
  """Diagnoses goma log files.

  Args:
    options: options
    args: a list of log files to be processed.  If none, it will read log files
          in options.logdir.
  Returns:
    0 if no critial error logs found.  1 when critial error logs found.
  """
  if args:
    compiler_proxy_infos = args
  else:
    compiler_proxy_infos = FindCompilerProxyInfos(options.logdir)
  if not compiler_proxy_infos:
    logging.error('no compiler_proxy INFO file found')
    return 1

  print(compiler_proxy_infos)

  log_created = None  # Initial LogLine.
  goma_revision = None
  goma_version = None
  goma_flags = None
  goma_limits = None

  # TaskLog for each compile type.
  # Each dict will have task id as key, TaskLog as value.
  tasks = {'compile': dict(), 'precompile': dict(), 'link': dict()}
  # Task's replies for each compile type.
  # Each dict will have task response as key, and counts as value.
  replies = {'compile': dict(), 'precompile': dict(), 'link': dict()}
  # List of failed tasks for each compile type.
  # Each list will be a list of TaskLogs.
  fail_tasks = {'compile': [], 'precompile': [], 'link': []}

  # Lists of LogLines for each loglevel.
  fatals = []
  errors = []
  warnings = []

  # Warnings that could be seen in normal cases.
  # key: regexp for a log text.
  # value: a format for key string of warnings_known. %s will be replaced
  #     with $1 for the key regexp.
  warnings_pattern = [
      (re.compile(
          r'.* \((.*)\) Using "defined" in macro causes undefined behavior.*'),
       'Using "defined" in macro causes undefined behavior %s'),
      (re.compile(r'.*Task:(.*) request didn\'t have full content.*'),
       'request missing input in Task:%s'),
  ]
  warnings_known = dict()

  uptime = 0
  slow_tasks = []
  slow_task_stats = SimpleStats()

  messages = []

  task_pendings = dict()

  durations_per_parallelism = DurationPerParallelism()

  crash_dump = ''

  error_task_ids = set()
  warning_task_ids = set()

  statz_output = ''
  json_statz_output = ''

  for logline in IterLoglines(IterLines(compiler_proxy_infos)):
    logging.debug('logline:%s', logline)
    if not log_created:
      log_created = logline
      continue

    if not durations_per_parallelism.last_time and logline.logtime:
      durations_per_parallelism.last_time = logline.logtime

    if logline.loglevel == 'F':
      fatals.append(logline)
    elif logline.loglevel == 'E':
      errors.append(logline)
    elif logline.loglevel == 'W':
      for pat, w in warnings_pattern:
        m = pat.match(logline.logtext)
        if m:
          warntype = w % m.group(1)
          warnings_known.setdefault(warntype, 0)
          warnings_known[warntype] += 1
          break
      else:
        warnings.append(logline)

    if not goma_revision:
      m = re.match('.*goma built revision (.*)', logline.logtext)
      if m:
        goma_revision = m.group(1)
        continue
    if not goma_version:
      m = re.match('.*goma version:(.*)', logline.logtext)
      if m:
        goma_version = m.group(1)
        continue
    if not goma_flags:
      m = re.match('.*goma flags:(.*)', logline.logtext, flags=re.DOTALL)
      if m:
        goma_flags = m.group(1)
        continue
    if not goma_limits:
      m = re.match('.*(max incoming:.*)', logline.logtext)
      if m:
        goma_limits = m.group(1)
        continue

    m = re.match('.*Crash Dump (.*)', logline.logtext)
    if m:
      crash_dump = m.group(1)
      continue

    m = re.match('.*Task:(\\d+) (.*)', logline.logtext)
    if m:
      # Task's LogLine.
      task_id = m.group(1)
      task_log = m.group(2)
      if logline.loglevel == 'E':
        error_task_ids.add(task_id)
      if logline.loglevel == 'W':
        warning_task_ids.add(task_id)
      m = re.match('Start (.*)', task_log)
      if m:
        # Task's start.
        task = TaskLog(task_id, m.group(1), logline.logtime)
        if task_pendings.get(task_id):
          task.loglines.extend(task_pendings[task_id])
          slow_tasks.append('Task:%s time to start: %s' % (
              task_id, (task.start_time - task.loglines[0].logtime)))
          slow_task_stats.Update(
              'start task too slow',
              (task.start_time - task.loglines[0].logtime).total_seconds())
          task.start_time = task.loglines[0].logtime
          del task_pendings[task_id]
        else:
          # just start now
          durations_per_parallelism.Start(logline.logtime)
        task.loglines.append(logline)
        tasks[task.compile_type][task.id] = task
        logging.info('task start: %s %s', task_id, task.compile_type)
        continue

      # Lookup the TaskLog by taskId.
      for compile_type in tasks:
        task = tasks[compile_type].get(task_id)
        if task:
          break
      if not task:
        # maybe, flag fail or pending.  e.g. b/6845420
        task_pendings.setdefault(task_id, [])
        task_pendings[task_id].append(logline)
        if len(task_pendings[task_id]) == 1:
          # start pending?
          durations_per_parallelism.Start(logline.logtime)
        logging.info('Task:%s log without Start: %s' % (
            task_id, logline.logtext))
        continue
      task.loglines.append(logline)
      m = re.match('ReplyResponse: (.*)', task_log)
      if m:
        # Task's response.
        task.end_time = logline.logtime
        task.response = m.group(1)
        durations_per_parallelism.Finish(logline.logtime)
        logging.info('task end: %s %s %s',
                     task_id, task.response, task.Duration())
        replies[task.compile_type].setdefault(task.response, 0)
        replies[task.compile_type][task.response] += 1
        if task.response == 'fail fallback':
          fail_tasks[task.compile_type].append(task)
        continue

    m = re.match('.*Dumping stats...(.*)', logline.logtext,
                 flags=re.DOTALL)
    if m:
      statz_output = m.group(1)

    json_stats = None
    m = re.match('.*Dumping json stats...(.*)', logline.logtext,
                 flags=re.DOTALL)
    if m:
      json_statz_output = m.group(1)
      json_stats = ParseJsonStats(json_statz_output)

    if json_stats:
      uptime = LongValueFromJsonStats(json_stats,
          ['stats', 'timeStats', 'uptime'])
      consuming_memory = LongValueFromJsonStats(json_stats,
          ['stats', 'memoryStats', 'consuming'])
      missed_files = LongValueFromJsonStats(json_stats,
          ['stats', 'fileStats', 'missed'])

      memory_threshold = options.memory_threshold
      if memory_threshold < 0:
        # Automatically configure memory threshold.
        gibibyte = 1024 * 1024 * 1024
        memory_threshold = 3 * gibibyte

      if consuming_memory and consuming_memory > memory_threshold:
        messages.append('Consumed too much memory: %d > %d' % (
                        consuming_memory, memory_threshold))

      if missed_files and missed_files > options.filemiss_threshold:
        messages.append('Too much missing files: %d > %d' % (
                        missed_files, options.filemiss_threshold))

  print(log_created.logtext)
  print()
  print('goma built revision %s' % goma_revision)
  print('goma version %s' % goma_version)
  print('goma flags %s' % goma_flags)
  print('goma limits %s' % goma_limits)

  print()
  for compile_type in tasks:
    print()
    print('%s: # of tasks: %d' % (compile_type, len(tasks[compile_type])))
    if tasks[compile_type]:
      print('   replies:')
      for resp, value in replies[compile_type].items():
        print('     %s : %d' % (resp, value))
      unfinished = []
      for task in tasks[compile_type].values():
        if not task.response:
          unfinished.append(task)
      if len(unfinished) > 0:
        messages.append('unfinished job %d' % len(unfinished))
        print('   unfinished: %d' % len(unfinished))
        for task in unfinished:
          print('     Task:%s - unfinished' % task.id)
          for logline in task.loglines:
            print('       %s %s' % (logline.logtime, logline.logtext))
          print()

      print('   durations:')
      durations = list(tasks[compile_type].values())
      total_duration = datetime.timedelta()
      durations.sort(key=lambda a: a.Duration())
      for d in durations:
        total_duration += d.Duration()
      print('       ave : %s' % (total_duration / len(durations)))
      print('       max : %s' % durations[-1].Duration())
      print('        98%%: %s' % durations[int(len(durations)*0.98)].Duration())
      print('        91%%: %s' % durations[int(len(durations)*0.91)].Duration())
      print('        75%%: %s' % durations[int(len(durations)*0.75)].Duration())
      print('        50%%: %s' % durations[int(len(durations)*0.50)].Duration())
      print('        25%%: %s' % durations[int(len(durations)*0.25)].Duration())
      print('         9%%: %s' % durations[int(len(durations)*0.09)].Duration())
      print('         2%%: %s' % durations[int(len(durations)*0.02)].Duration())
      print('       min : %s' % durations[0].Duration())
      print('   long tasks:')
      for i in range(min(3, len(durations))):
        task = durations[-(i + 1)]
        print('   #%d %s Task:%s' % (i + 1, task.Duration(), task.id))
        print('       %s' % task.desc)
        print('       %s' % task.response)
      if fail_tasks[compile_type]:
        if len(fail_tasks[compile_type]) > options.fail_tasks_threshold:
          messages.append('Too many fail tasks in %s: %d > %d' % (
              compile_type, len(fail_tasks[compile_type]),
              options.fail_tasks_threshold))
        print('   fail tasks:')
        for i in range(min(3, len(fail_tasks[compile_type]))):
          task = fail_tasks[compile_type][i]
          print('    Task:%s' % task.id)
          print('      %s' % task.desc)
          for logline in task.loglines:
            print('       %s %s' % (logline.logtime, logline.logtext))

  if crash_dump:
    messages.append('CRASH dump exists')
    print()
    print('Crash')
    print(crash_dump)

  if statz_output:
    print()
    print('Goma stats: ', statz_output)

  if json_statz_output:
    print()
    print('Goma json stats: ', json_statz_output)

  print()
  print('Duration per num active tasks')
  for p in durations_per_parallelism.durations:
    print(' %d tasks: %s' % (p, durations_per_parallelism.durations[p]))

  if fatals:
    messages.append('FATAL log exists: %s' % len(fatals))
    print()
    print('Fatal')
    for fatal in fatals:
      print(fatal)
  if len(error_task_ids) > options.errors_threshold:
    messages.append('Task having ERROR log exists: %s > %s' % (
        len(error_task_ids), options.errors_threshold))
  if options.show_errors and errors:
    print()
    print('Error')
    for error in errors:
      print(error)
  if warnings_known:
    print()
    warnings_known_out = []
    for warntype, count in warnings_known.items():
      if count > options.show_known_warnings_threshold:
        warnings_known_out.append('  %d: %s' % (count, warntype))
    if warnings_known_out:
      print('Known warning')
      for warning in warnings_known_out:
        print(warning)
  if len(warning_task_ids) > options.warnings_threshold:
    messages.append('Task having WARNING log exists: %s > %s' % (
        len(warning_task_ids), options.warnings_threshold))
  if options.show_warnings and warnings:
    print()
    print('Warning')
    for warning in warnings:
      print(warning)

  if (len(slow_tasks) > 0 and
      uptime > options.show_slow_tasks_if_uptime_longer_than_sec):
    options.show_slow_tasks = True
    for key, value in slow_task_stats.stats.items():
      messages.append('%s: num=%d, longest=%s' % (
          key, value['num'], value['max']))

  if options.show_slow_tasks and slow_tasks:
    print()
    print('SLOW Tasks')
    for slow_task in slow_tasks:
      print(slow_task)

  if options.output_json:
    summary = {
        'stats': {
            'fatal': len(fatals),
            'error': len(errors),
            'warning': len(warnings),
        },
        'messages': messages,
        'goma_revision': goma_revision,
        'goma_version': goma_version,
        'uptime': uptime,
    }
    with open(options.output_json, 'w') as f:
      json.dump(summary, f)

  if messages:
    print()
    for msg in messages:
      print(msg)
    return 1
  return 0


def GetGlogDir():
  """Get glog directory.

  It should match the logic with GetTempDirectories in
  third_party/glog/src/logging.cc
  On Windows, GetTempPathA will be $TMP, $TEMP, $USERPROFILE and the Windows
  directory.
  http://msdn.microsoft.com/ja-jp/library/windows/desktop/aa364992(v=vs.85).aspx

  Returns:
    a directory name.
  """
  candidates = [os.environ.get('TEST_TMPDIR', ''),
                os.environ.get('TMPDIR', ''),
                os.environ.get('TMP', '')]
  for tmpdir in candidates:
    if os.path.isdir(tmpdir):
      return tmpdir
  return '/tmp'


def main():
  option_parser = optparse.OptionParser()
  option_parser.add_option('', '--logdir', default=GetGlogDir(),
                           help='directory in which compiler_proxy.INFO exits')
  option_parser.add_option('', '--show-errors', action='store_true',
                           default=True,
                           help='show error log messages')
  option_parser.add_option('', '--no-show-errors', action='store_false',
                           dest='show_errors',
                           help='do not show error log messages')
  option_parser.add_option('', '--show-warnings', action='store_true',
                           default=False,
                           help='show warning log messages')
  option_parser.add_option('', '--no-show-warnings', action='store_false',
                           dest='show_warnings',
                           help='do not show warning log messages')
  option_parser.add_option('', '--show-known-warnings-threshold',
                           default=5,
                           help='show known warnings threshold')
  option_parser.add_option('', '--fail-tasks-threshold',
                           default=0,
                           help='threshold for fail tasks')
  option_parser.add_option('', '--errors-threshold',
                           default=10,
                           help='threshold for ERROR logs')
  option_parser.add_option('', '--warnings-threshold',
                           default=100,
                           help='threshold for WARNING logs')
  option_parser.add_option('', '--show-slow-tasks', action='store_true',
                           default=False,
                           help='show slow tasks')
  option_parser.add_option('', '--no-show-slow-tasks', action='store_false',
                           dest='show_slow_tasks',
                           help='do not show slow tasks')
  option_parser.add_option('', '--show-slow-tasks-if-uptime-longer-than-sec',
                           default=2700,
                           help='show slow tasks if compiler_proxy uptime is'
                                'longer than this seconds')
  option_parser.add_option('', '--memory-threshold',
                           default=-1,
                           help='threshold for memory comsuption. '
                                'automatically configured if negative')
  option_parser.add_option('', '--filemiss-threshold',
                           default=30000,
                           help="threshold for file missed")
  option_parser.add_option('-v', '--verbose', action='count', default=0,
                           help='verbose logging')
  option_parser.add_option('-o', '--output-json',
                           help='Output JSON information into a specified file')
  options, args = option_parser.parse_args()
  if options.verbose >= 2:
    logging.basicConfig(level=logging.DEBUG)
  elif options.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.WARNING)

  return DiagnoseGomaLog(options, args)


if '__main__' == __name__:
  sys.exit(main())
