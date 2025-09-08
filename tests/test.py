#!/usr/bin/env python3

import os
import pathlib
import subprocess
from datetime import datetime

DIRNAME = os.path.dirname(os.path.abspath(__file__))
MAINDIR = os.path.dirname(DIRNAME)


def compare_directories(actual: pathlib.Path, expected: pathlib.Path, log_file):
    actual_files = sorted(
        f.relative_to(actual) for f in actual.rglob("*") if f.is_file()
    )
    expected_files = sorted(
        f.relative_to(expected) for f in expected.rglob("*") if f.is_file()
    )

    assert actual_files == expected_files, "Mismatch in file names/structure"

    for rel_path in actual_files:
        # skip sb files as they are checked separately
        if rel_path.suffix == ".sb":
            continue

        else:
            actual_content = (actual / rel_path).read_bytes()
            expected_content = (expected / rel_path).read_bytes()
            assert actual_content == expected_content, f"Mismatch in file: {rel_path}"

    parser_proc = subprocess.run(
        [
            os.path.join(MAINDIR, "sb_parser", "parser"),
            (actual / "rev_profiles"),
            (expected / "rev_profiles"),
        ],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    assert parser_proc.returncode == 0, "Mismatch in sb files"


def build_image():
    name = f'sandblaster_{datetime.now().strftime("%d_%m_%Y__%H_%M_%S")}'

    log_path = os.path.join(DIRNAME, "build_logs", f"{name}.log")
    log_file = open(log_path, "w")

    docker_build_process = subprocess.run(
        ["docker", "build", "-t", name, MAINDIR],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    if docker_build_process.returncode != 0:
        print(
            f"[ERROR] Docker build failed, check build_logs/{name}.log for more details :("
        )
        return 1

    print(f"[INFO] Docker build {name} successful")
    return name


def remove_image(container_name):
    print(f"[INFO] Removing container {container_name}")

    subprocess.run(["docker", "rmi", "-f", container_name])


def start_run(container_name, test_name):
    run_name = f"run_{container_name}_{test_name}"

    test_path = os.path.join(DIRNAME, test_name)

    run_process = subprocess.run(
        [
            "docker",
            "run",
            "-v",
            f"{test_path}:/test",
            "--rm",
            "-dit",
            "--name",
            run_name,
            container_name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    print(f"[INFO] Run ID: {run_process.stdout}")

    return run_name


def stop_run(run_name):
    stop_process = subprocess.run(
        ["docker", "stop", run_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    print(f"[INFO] Stopped run {stop_process.stdout}")


def generic_test(
    container_name, test_name, ios_major_version, ios_version, update_refs=False
):
    print(f"[INFO] Running sandblaster test {test_name} (iOS v{ios_major_version})...")

    run_name = start_run(container_name, test_name)

    log_path = os.path.join(DIRNAME, test_name, "logs", f"{run_name}.log")
    log_file = open(log_path, "a")

    subprocess.run(
        ["docker", "exec", run_name, "rm", "-rf", "/test/outputs"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    subprocess.run(
        ["docker", "exec", run_name, "mkdir", "/test/outputs"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    subprocess.run(
        [
            "docker",
            "exec",
            run_name,
            "/sandblaster/helpers/extract_sandbox_data.py",
            "-o",
            "/test/outputs/sb_ops",
            "/test/inputs/sandbox.kext",
            ios_version,
        ],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    if ios_major_version >= 9:
        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "/sandblaster/helpers/extract_sandbox_data.py",
                "-O",
                "/test/outputs",
                "/test/inputs/sandbox.kext",
                ios_version,
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    else:
        subprocess.run(
            ["docker", "exec", run_name, "mkdir", "-p", "/test/outputs/sb_profiles"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "/sandblaster/helpers/extract_sandbox_data.py",
                "-O",
                "/test/outputs/sb_profiles",
                "/test/inputs/sandboxd",
                ios_version,
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    subprocess.run(
        ["docker", "exec", run_name, "mkdir", "/test/outputs/rev_profiles"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    if ios_major_version >= 9:
        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "sh",
                "-c",
                f"cd /sandblaster/reverse-sandbox/ && python2.7 reverse_sandbox.py -r {ios_version} "
                + "-o /test/outputs/sb_ops -d /test/outputs/rev_profiles/ /test/outputs/sandbox_bundle "
                + "-psb > /test/outputs/sandbox_profiles.txt",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "sh",
                "-c",
                f"cd /sandblaster/reverse-sandbox/ && python2.7 reverse_sandbox.py -r {ios_version} "
                + "-o /test/outputs/sb_ops -d /test/outputs/rev_profiles/ /test/outputs/sandbox_bundle",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    else:
        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "sh",
                "-c",
                "cd /sandblaster/reverse-sandbox/ && for i in /test/outputs/sb_profiles/*; do "
                + f"python2.7 reverse_sandbox.py -r {ios_version} -o /test/outputs/sb_ops -d "
                + '/test/outputs/rev_profiles/ "$i"; done',
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    if update_refs:
        subprocess.run(
            ["docker", "exec", run_name, "rm", "-rf", "/test/references"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        subprocess.run(
            [
                "docker",
                "exec",
                run_name,
                "cp",
                "-r",
                "/test/outputs",
                "/test/references",
            ],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        return

    print(f"[INFO] {test_name}: comparing results...")

    output_dir = pathlib.Path(DIRNAME, test_name, "outputs")
    reference_dir = pathlib.Path(DIRNAME, test_name, "references")

    try:
        compare_directories(output_dir, reference_dir, log_file)

        print(f"[PASS] {test_name} :)")
    except AssertionError as err:
        print(f"[FAIL] {test_name} - {err}")

    stop_run(run_name)


def main():
    container_name = build_image()

    generic_test(container_name, "iPhone5__1_9.3_13E237", 9, ios_version="9.3")

    remove_image(container_name)


main()
