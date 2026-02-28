"""Tests for Dockerfile and .dockerignore correctness (static analysis only)."""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _dockerfile_lines():
    """Return non-empty, non-comment lines from the Dockerfile."""
    text = DOCKERFILE.read_text()
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _dockerfile_instructions():
    """Return a list of (INSTRUCTION, rest) tuples from the Dockerfile."""
    instructions = []
    for line in _dockerfile_lines():
        match = re.match(r"^([A-Z]+)\s+(.*)", line)
        if match:
            instructions.append((match.group(1), match.group(2)))
    return instructions


# -------------------------------------------------------------------
# 1. File existence
# -------------------------------------------------------------------
class TestFileExistence:
    def test_dockerfile_exists(self):
        assert DOCKERFILE.is_file(), "Dockerfile must exist at project root"

    def test_dockerignore_exists(self):
        assert DOCKERIGNORE.is_file(), ".dockerignore must exist at project root"


# -------------------------------------------------------------------
# 2. Dockerfile basic syntax
# -------------------------------------------------------------------
class TestDockerfileSyntax:
    def test_has_at_least_one_instruction(self):
        instructions = _dockerfile_instructions()
        assert len(instructions) >= 1, "Dockerfile must contain at least one instruction"

    def test_first_instruction_is_from(self):
        instructions = _dockerfile_instructions()
        assert instructions[0][0] == "FROM", "First instruction must be FROM"

    def test_no_empty_file(self):
        text = DOCKERFILE.read_text()
        assert len(text.strip()) > 0, "Dockerfile must not be empty"


# -------------------------------------------------------------------
# 3. Required instructions
# -------------------------------------------------------------------
class TestRequiredInstructions:
    def test_has_from(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "FROM" in names

    def test_has_copy(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "COPY" in names

    def test_has_run(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "RUN" in names

    def test_has_entrypoint(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "ENTRYPOINT" in names

    def test_has_cmd(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "CMD" in names


# -------------------------------------------------------------------
# 4. FROM uses python 3.12 slim
# -------------------------------------------------------------------
class TestBaseImage:
    def test_base_image_is_python_3_12_slim(self):
        text = DOCKERFILE.read_text()
        assert re.search(r"FROM\s+python:3\.12-slim", text), (
            "Base image must be python:3.12-slim"
        )


# -------------------------------------------------------------------
# 5. pip install is present
# -------------------------------------------------------------------
class TestPipInstall:
    def test_pip_install_present(self):
        text = DOCKERFILE.read_text()
        assert "pip install" in text, "Dockerfile must contain a pip install step"

    def test_no_cache_dir_used(self):
        text = DOCKERFILE.read_text()
        assert "--no-cache-dir" in text, (
            "pip install should use --no-cache-dir to reduce image size"
        )


# -------------------------------------------------------------------
# 6. Entrypoint is na0s
# -------------------------------------------------------------------
class TestEntrypoint:
    def test_entrypoint_is_na0s(self):
        text = DOCKERFILE.read_text()
        match = re.search(r'ENTRYPOINT\s+\[([^\]]+)\]', text)
        assert match, "ENTRYPOINT must use exec form (JSON array)"
        assert '"na0s"' in match.group(1), (
            'ENTRYPOINT must reference "na0s"'
        )


# -------------------------------------------------------------------
# 7. CMD default
# -------------------------------------------------------------------
class TestCmdDefault:
    def test_cmd_provides_default(self):
        text = DOCKERFILE.read_text()
        match = re.search(r'CMD\s+\[([^\]]+)\]', text)
        assert match, "CMD must use exec form (JSON array)"
        assert '"--help"' in match.group(1), (
            'CMD default should be "--help"'
        )


# -------------------------------------------------------------------
# 8. Non-root user
# -------------------------------------------------------------------
class TestNonRootUser:
    def test_user_instruction_present(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "USER" in names, "Dockerfile must switch to a non-root USER"

    def test_user_is_not_root(self):
        for instr, arg in _dockerfile_instructions():
            if instr == "USER":
                assert arg.strip() != "root", "USER must not be root"


# -------------------------------------------------------------------
# 9. Labels
# -------------------------------------------------------------------
class TestLabels:
    def test_has_maintainer_label(self):
        text = DOCKERFILE.read_text()
        assert re.search(r'LABEL\s+maintainer=', text), (
            "Dockerfile should have a maintainer label"
        )

    def test_has_version_label(self):
        text = DOCKERFILE.read_text()
        assert re.search(r'LABEL\s+version=', text), (
            "Dockerfile should have a version label"
        )

    def test_has_description_label(self):
        text = DOCKERFILE.read_text()
        assert re.search(r'LABEL\s+description=', text), (
            "Dockerfile should have a description label"
        )


# -------------------------------------------------------------------
# 10. Multi-stage build
# -------------------------------------------------------------------
class TestMultiStageBuild:
    def test_has_multiple_from_instructions(self):
        froms = [i for i in _dockerfile_instructions() if i[0] == "FROM"]
        assert len(froms) >= 2, (
            "Dockerfile should use multi-stage build (multiple FROM instructions)"
        )

    def test_builder_stage_named(self):
        text = DOCKERFILE.read_text()
        assert re.search(r"FROM\s+\S+\s+AS\s+builder", text, re.IGNORECASE), (
            "First stage should be named 'builder'"
        )


# -------------------------------------------------------------------
# 11. Layer caching strategy
# -------------------------------------------------------------------
class TestLayerCaching:
    def test_pyproject_copied_before_full_source(self):
        """pyproject.toml should be copied before the full COPY . to leverage
        Docker layer caching for dependency installation."""
        text = DOCKERFILE.read_text()
        pyproject_pos = text.find("COPY pyproject.toml")
        full_copy_pos = text.find("COPY . .")
        assert pyproject_pos != -1, (
            "Dockerfile should COPY pyproject.toml separately"
        )
        assert full_copy_pos != -1, (
            "Dockerfile should COPY . . for the full source"
        )
        assert pyproject_pos < full_copy_pos, (
            "pyproject.toml must be copied before the full source tree "
            "to enable Docker layer caching for dependencies"
        )


# -------------------------------------------------------------------
# 12. WORKDIR is set
# -------------------------------------------------------------------
class TestWorkdir:
    def test_workdir_present(self):
        names = {i[0] for i in _dockerfile_instructions()}
        assert "WORKDIR" in names, "Dockerfile must set a WORKDIR"


# -------------------------------------------------------------------
# 13. .dockerignore contents
# -------------------------------------------------------------------
class TestDockerignoreContents:
    @pytest.fixture()
    def ignore_entries(self):
        return DOCKERIGNORE.read_text().splitlines()

    @pytest.mark.parametrize(
        "pattern",
        [
            ".git/",
            "__pycache__/",
            "*.pyc",
            ".pytest_cache/",
            ".coverage",
            "htmlcov/",
            "dist/",
            "build/",
            "*.egg-info",
            ".env",
            "venv/",
            ".venv/",
            "data/raw/",
            ".claude/",
            "node_modules/",
        ],
    )
    def test_pattern_in_dockerignore(self, ignore_entries, pattern):
        assert pattern in ignore_entries, (
            f".dockerignore must contain '{pattern}'"
        )
