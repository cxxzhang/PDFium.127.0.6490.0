use_relative_paths = True

hooks = [
  {
    'name': 'msan_chained_origins_focal',
    'pattern': '.',
    'condition': 'checkout_instrumented_libraries',
    'action': [ 'python3',
                '../depot_tools/download_from_google_storage.py',
                '--extract',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-instrumented-libraries',
                '-s', 'binaries/msan-chained-origins-focal-lib.tar.gz.sha1',
              ],
  },
  {
    'name': 'msan_no_origins_focal',
    'pattern': '.',
    'condition': 'checkout_instrumented_libraries',
    'action': [ 'python3',
                '../depot_tools/download_from_google_storage.py',
                '--extract',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-instrumented-libraries',
                '-s', 'binaries/msan-no-origins-focal-lib.tar.gz.sha1',
              ],
  },
]
