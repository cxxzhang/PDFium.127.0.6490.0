#!/usr/bin/env python3
# Copyright 2016 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Builds and packages instrumented libraries for dynamic tools."""

import argparse
import multiprocessing
import os
import subprocess
import tarfile

BUILD_TYPES = {
    "msan-no-origins": [
        "is_msan = true",
        "msan_track_origins = 0",
    ],
    "msan-chained-origins": [
        "is_msan = true",
        "msan_track_origins = 2",
    ],
}

IGNORED_SUFFIXES = [
    ".txt",
    # Skip a missing symlink.
    "99-environment.conf",
]


class Error(Exception):
    pass


class IncorrectReleaseError(Error):
    pass


def _get_release():
    return subprocess.check_output(["lsb_release",
                                    "-cs"]).decode("utf-8").strip()


def _tar_filter(tar_info):
    if any(tar_info.name.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return None
    return tar_info


def build_libraries(build_type, ubuntu_release, jobs, use_remoteexec):
    build_dir = "out/Instrumented-%s" % build_type
    if not os.path.exists(build_dir):
        os.makedirs(build_dir)

    gn_args = [
        "is_debug = false",
        "use_remoteexec = %s" % str(use_remoteexec).lower(),
        "use_locally_built_instrumented_libraries = true",
        'instrumented_libraries_release = "%s"' % ubuntu_release,
    ] + BUILD_TYPES[build_type]
    with open(os.path.join(build_dir, "args.gn"), "w") as f:
        f.write("\n".join(gn_args) + "\n")
    subprocess.check_call(["gn", "gen", build_dir, "--check"])
    subprocess.check_call([
        "ninja",
        "-j%d" % jobs,
        "-C",
        build_dir,
        "third_party/instrumented_libs/%s:locally_built" % ubuntu_release,
    ])
    release = _get_release()
    name = '%s-%s-lib' % (build_type, release)
    with tarfile.open("%s.tar.gz" % name, mode="w:gz") as f:
        f.add(
            "%s/instrumented_libraries/lib" % build_dir,
            arcname=name + "/lib",
            filter=_tar_filter,
        )
        f.add(
            "%s/instrumented_libraries/sources" % build_dir,
            arcname=name + "/sources",
            filter=_tar_filter,
        )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=8,
        help="the default number of jobs to use when running ninja",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        default=False,
        help="whether to run all instrumented builds in parallel",
    )
    parser.add_argument(
        "--use_remoteexec",
        action="store_true",
        default=False,
        help="whether to use goma to compile",
    )
    parser.add_argument(
        "build_type",
        nargs="*",
        default="all",
        choices=list(BUILD_TYPES.keys()) + ["all"],
        help="the type of instrumented library to build",
    )
    parser.add_argument("release",
                        help="the name of the Ubuntu release to build with")
    args = parser.parse_args()
    if args.build_type == "all" or "all" in args.build_type:
        args.build_type = BUILD_TYPES.keys()

    if args.release != _get_release():
        raise IncorrectReleaseError(
            "trying to build for %s but the current release is %s" %
            (args.release, _get_release()))
    build_types = sorted(set(args.build_type))
    if args.parallel:
        procs = []
        for build_type in build_types:
            proc = multiprocessing.Process(
                target=build_libraries,
                args=(build_type, args.release, args.jobs, args.use_remoteexec),
            )
            proc.start()
            procs.append(proc)
        for proc in procs:
            proc.join()
    else:
        for build_type in build_types:
            build_libraries(build_type, args.release, args.jobs, args.use_remoteexec)
    print("To upload, run:")
    for build_type in build_types:
        print("upload_to_google_storage.py -b "
              "chromium-instrumented-libraries %s-%s.tgz" %
              (build_type, args.release))
    print("You should then commit the resulting .sha1 files.")


if __name__ == "__main__":
    main()
