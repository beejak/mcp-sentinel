"""
Diff Builder for generating git-style diffs from code changes.
"""

import difflib
from typing import List, Optional
from mcp_sentinel.remediation.models import CodeChange


class DiffBuilder:
    """Helper class to generate unified diffs."""

    @staticmethod
    def generate_diff(code_change: CodeChange) -> str:
        """
        Generate a unified diff for a code change.

        Args:
            code_change: The code change object containing original and new code.

        Returns:
            String containing the unified diff.
        """
        # Ensure we have lines with newlines for difflib
        original_lines = code_change.original_code.splitlines(keepends=True)
        if not original_lines and code_change.original_code:
            # Handle case where single line has no newline
            original_lines = [code_change.original_code + "\n"]
            
        new_lines = code_change.new_code.splitlines(keepends=True)
        if not new_lines and code_change.new_code:
            new_lines = [code_change.new_code + "\n"]

        # If strings are identical, return empty string
        if code_change.original_code == code_change.new_code:
            return ""

        # Generate diff
        # We assume the code snippets are comparable chunks
        diff_iter = difflib.unified_diff(
            original_lines,
            new_lines,
            fromfile=f"a/{code_change.file_path}",
            tofile=f"b/{code_change.file_path}",
            lineterm=""
        )
        
        diff_text = "".join(diff_iter)
        
        # If the diff is empty but codes are different (e.g. whitespace only and ignored?)
        # difflib.unified_diff doesn't ignore whitespace by default, so this should be fine.
        
        return diff_text

    @staticmethod
    def apply_patch(original_content: str, code_change: CodeChange) -> str:
        """
        Apply a code change to the original file content.
        
        Args:
            original_content: Full content of the original file
            code_change: The change to apply
            
        Returns:
            New file content
        """
        lines = original_content.splitlines(keepends=True)
        
        # Adjust 1-based line numbers to 0-based index
        start_idx = max(0, code_change.start_line - 1)
        end_idx = min(len(lines), code_change.end_line)
        
        # Replace the chunk
        # Note: This is a simple replacement based on line numbers.
        # For more robust patching, we might want to verify content matches.
        
        before = lines[:start_idx]
        after = lines[end_idx:]
        
        new_chunk = code_change.new_code
        if not new_chunk.endswith("\n") and (after or len(lines) > end_idx):
             # Ensure newline if inserting into middle of file
             new_chunk += "\n"
             
        return "".join(before) + new_chunk + "".join(after)
