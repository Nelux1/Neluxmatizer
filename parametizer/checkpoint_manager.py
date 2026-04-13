#!/usr/bin/env python3
"""
Checkpoint system for saving and resuming URL list scans.
Allows continuing from where it left off if the scan is interrupted.
"""

import os
import json
import hashlib
import sys
from pathlib import Path


class CheckpointManager:
    """Manages saving and loading checkpoints for URL list scans."""
    
    def __init__(self, checkpoint_dir=None):
        """
        Initialize the checkpoint manager.
        
        Args:
            checkpoint_dir: Directory where checkpoints are saved (default: output/.checkpoints)
        """
        if checkpoint_dir is None:
            wd = os.environ.get("NELUXMATIZER_WORKDIR")
            if wd:
                checkpoint_dir = os.path.join(wd, "output", ".checkpoints")
            else:
                checkpoint_dir = os.path.join("output", ".checkpoints")
        
        self.checkpoint_dir = checkpoint_dir
        self._ensure_checkpoint_dir()
    
    def _ensure_checkpoint_dir(self):
        """Ensures the checkpoint directory exists."""
        try:
            os.makedirs(self.checkpoint_dir, exist_ok=True)
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not create checkpoint directory: {e}\033[0m\n')
            sys.stdout.flush()
    
    def _generate_checkpoint_id(self, list_file, scan_params):
        """
        Generate a unique ID for the checkpoint based on the list file and scan parameters.
        
        Args:
            list_file: Path to the URL list file
            scan_params: Dictionary with scan parameters (vulnerabilities, threads, etc.)
        
        Returns:
            str: Unique checkpoint ID
        """
        # Normalize file path
        list_file = os.path.abspath(os.path.expanduser(list_file))
        
        # Create hash of file content + parameters
        try:
            with open(list_file, 'rb') as f:
                file_content = f.read()
        except Exception:
            file_content = list_file.encode()
        
        # Create unique string with file + parameters
        unique_string = f"{file_content}{json.dumps(scan_params, sort_keys=True)}"
        
        # Generate MD5 hash
        checkpoint_id = hashlib.md5(unique_string.encode()).hexdigest()
        
        return checkpoint_id
    
    def get_checkpoint_file(self, checkpoint_id):
        """
        Get the checkpoint file path.
        
        Args:
            checkpoint_id: Checkpoint ID
        
        Returns:
            str: Full path to the checkpoint file
        """
        return os.path.join(self.checkpoint_dir, f"checkpoint_{checkpoint_id}.json")
    
    def save_checkpoint(self, checkpoint_id, data):
        """
        Save a checkpoint.
        
        Args:
            checkpoint_id: Unique checkpoint ID
            data: Dictionary with checkpoint data
        
        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            checkpoint_file = self.get_checkpoint_file(checkpoint_id)
            
            # Add timestamp
            import time
            data['last_updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Save to JSON file
            with open(checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not save checkpoint: {e}\033[0m\n')
            sys.stdout.flush()
            return False
    
    def load_checkpoint(self, checkpoint_id):
        """
        Load a checkpoint.
        
        Args:
            checkpoint_id: Checkpoint ID to load
        
        Returns:
            dict: Checkpoint data or None if it doesn't exist
        """
        try:
            checkpoint_file = self.get_checkpoint_file(checkpoint_id)
            
            if not os.path.exists(checkpoint_file):
                return None
            
            with open(checkpoint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return data
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not load checkpoint: {e}\033[0m\n')
            sys.stdout.flush()
            return None
    
    def checkpoint_exists(self, checkpoint_id):
        """
        Check if a checkpoint exists.
        
        Args:
            checkpoint_id: Checkpoint ID
        
        Returns:
            bool: True if exists, False otherwise
        """
        checkpoint_file = self.get_checkpoint_file(checkpoint_id)
        return os.path.exists(checkpoint_file)
    
    def delete_checkpoint(self, checkpoint_id):
        """
        Delete a checkpoint.
        
        Args:
            checkpoint_id: Checkpoint ID to delete
        
        Returns:
            bool: True if deleted successfully, False otherwise
        """
        try:
            checkpoint_file = self.get_checkpoint_file(checkpoint_id)
            if os.path.exists(checkpoint_file):
                os.remove(checkpoint_file)
                return True
            return False
        except Exception as e:
            sys.stdout.write(f'\033[1;33m[⚠️] Warning: Could not delete checkpoint: {e}\033[0m\n')
            sys.stdout.flush()
            return False
    
    def get_processed_urls(self, checkpoint_id):
        """
        Get the list of already processed URLs from a checkpoint.
        
        Args:
            checkpoint_id: Checkpoint ID
        
        Returns:
            list: List of processed URLs
        """
        checkpoint_data = self.load_checkpoint(checkpoint_id)
        if checkpoint_data:
            return checkpoint_data.get('processed_urls', [])
        return []
    
    def filter_pending_urls(self, all_urls, processed_urls):
        """
        Filter URLs pending to be processed.
        
        Args:
            all_urls: Complete list of URLs
            processed_urls: List of already processed URLs
        
        Returns:
            list: URLs pending to be processed
        """
        processed_set = set(processed_urls)
        return [url for url in all_urls if url not in processed_set]
