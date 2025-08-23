#!/usr/bin/env python3
"""
Dark Web Threat Intelligence Analyzer - Main Orchestrator

This module orchestrates the complete pipeline for processing leaked credential files:
1. Parsing leaked files to extract credentials
2. Uploading processed data to Elasticsearch
3. Cleaning up temporary files

Author: Yousef
Project: Dark Web Threat Intelligence Analyzer
"""

import subprocess
import sys
import os
import glob
import logging
import argparse
from pathlib import Path
from typing import Optional, List
from datetime import datetime

try:
    from src.config.config import config, ConfigurationError
    from src.utils.logging_config import LoggingManager
except ImportError as e:
    print(f"Error importing configuration: {e}")
    print("Please ensure the src.config module is properly installed.")
    sys.exit(1)

class PipelineError(Exception):
    """Custom exception for pipeline-related errors."""
    pass

class LeakAnalyzerPipeline:
    """Main pipeline orchestrator for the Dark Web Threat Intelligence Analyzer."""
    
    def __init__(self, batch_mode: bool = False, log_level: str = None):
        """Initialize the pipeline with configuration and logging."""
        self.batch_mode = batch_mode
        self.setup_logging(log_level)
        self.logger = logging.getLogger(__name__)
        
        # Validate configuration
        try:
            self.config = config
            self.logger.info(f"Pipeline initialized with config: {self.config}")
        except ConfigurationError as e:
            self.logger.error(f"Configuration error: {e}")
            raise PipelineError(f"Failed to initialize pipeline: {e}")
    
    def setup_logging(self, log_level: str = None) -> None:
        """Configure logging for the pipeline using the comprehensive logging system."""
        # Use log level from command line, config, or default to INFO
        if log_level is None:
            log_level = getattr(config, 'LOG_LEVEL', 'INFO')
        
        # Initialize the comprehensive logging system
        logging_manager = LoggingManager()
        logging_manager.setup_logging(
            level=log_level,
            enable_file_logging=True,
            enable_console_logging=True,
            enable_performance_logging=False
        )
    
    def run_parser(self) -> bool:
        """Execute the leak parser module."""
        self.logger.info("Starting leak parsing process...")
        try:
            # Ensure input directory exists
            input_dir = Path(self.config.DOWNLOAD_ROOT)
            if not input_dir.exists():
                self.logger.warning(f"Input directory {input_dir} does not exist. Creating it.")
                input_dir.mkdir(parents=True, exist_ok=True)
            
            # Ensure output directory exists
            output_dir = Path(self.config.PARSED_OUTPUT_DIR)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Run parser
            result = subprocess.run(
                [sys.executable, "-m", "src.parser.leak_parser"],
                check=True,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            self.logger.info("Leak parsing completed successfully")
            if result.stdout:
                self.logger.debug(f"Parser output: {result.stdout}")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Parser process timed out after 1 hour")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Parser failed with exit code {e.returncode}")
            if e.stderr:
                self.logger.error(f"Parser error output: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during parsing: {e}")
            return False
    
    def upload_to_elasticsearch(self) -> bool:
        """Upload processed data to Elasticsearch."""
        self.logger.info("Starting Elasticsearch upload process...")
        try:
            # Check if parsed files exist
            parsed_dir = Path(self.config.PARSED_OUTPUT_DIR)
            if not parsed_dir.exists() or not any(parsed_dir.glob("*.json")):
                self.logger.warning(f"No parsed JSON files found in {parsed_dir}")
                return False
            
            # Run Elasticsearch uploader with parsed directory path
            result = subprocess.run(
                [sys.executable, "-m", "src.elasticsearch.upload_leaks_to_es", str(parsed_dir)],
                check=True,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            self.logger.info("Elasticsearch upload completed successfully")
            if result.stdout:
                self.logger.debug(f"Upload output: {result.stdout}")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Elasticsearch upload timed out after 30 minutes")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Elasticsearch upload failed with exit code {e.returncode}")
            if e.stderr:
                self.logger.error(f"Upload error output: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during Elasticsearch upload: {e}")
            return False
    
    def cleanup_json_files(self, force: bool = False) -> bool:
        """Clean up processed JSON files."""
        self.logger.info("Starting cleanup process...")
        try:
            json_dir = Path(self.config.PARSED_OUTPUT_DIR)
            if not json_dir.exists():
                self.logger.info(f"Directory {json_dir} does not exist. Nothing to clean.")
                return True
            
            json_files = list(json_dir.glob("*.json"))
            if not json_files:
                self.logger.info("No JSON files found to clean up")
                return True
            
            if not force and not self.batch_mode:
                response = self.ask_user(f"Delete {len(json_files)} JSON files from {json_dir}?")
                if not response:
                    self.logger.info("Cleanup cancelled by user")
                    return True
            
            deleted_count = 0
            failed_files = []
            
            for json_file in json_files:
                try:
                    json_file.unlink()
                    deleted_count += 1
                    self.logger.debug(f"Deleted: {json_file}")
                except Exception as e:
                    failed_files.append(str(json_file))
                    self.logger.warning(f"Failed to delete {json_file}: {e}")
            
            self.logger.info(f"Cleanup completed: {deleted_count} files deleted")
            if failed_files:
                self.logger.warning(f"Failed to delete {len(failed_files)} files: {failed_files}")
            
            return len(failed_files) == 0
            
        except Exception as e:
            self.logger.error(f"Unexpected error during cleanup: {e}")
            return False
    
    def ask_user(self, question: str) -> bool:
        """Prompt user for yes/no input with validation."""
        if self.batch_mode:
            self.logger.info(f"Batch mode: automatically answering 'yes' to: {question}")
            return True
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                user_input = input(f"\n{question} (yes/no): ").strip().lower()
                if user_input in ["yes", "y", "true", "1"]:
                    return True
                elif user_input in ["no", "n", "false", "0"]:
                    return False
                else:
                    print("Invalid input. Please enter 'yes' or 'no'.")
                    if attempt == max_attempts - 1:
                        print("Too many invalid attempts. Defaulting to 'no'.")
                        return False
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled by user.")
                return False
        
        return False
    
    def run_pipeline(self, steps: Optional[List[str]] = None) -> bool:
        """Execute the complete pipeline or specified steps."""
        self.logger.info("=" * 60)
        self.logger.info("Dark Web Threat Intelligence Analyzer Pipeline Started")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        self.logger.info("=" * 60)
        
        available_steps = {
            "parse": ("Run leak parser", self.run_parser),
            "upload": ("Upload to Elasticsearch", self.upload_to_elasticsearch),
            "cleanup": ("Clean up JSON files", self.cleanup_json_files)
        }
        
        if steps is None:
            steps = list(available_steps.keys())
        
        success_count = 0
        total_steps = len(steps)
        
        for step in steps:
            if step not in available_steps:
                self.logger.error(f"Unknown step: {step}")
                continue
            
            step_name, step_func = available_steps[step]
            
            if not self.batch_mode and not self.ask_user(step_name + "?"):
                self.logger.info(f"Skipping step: {step_name}")
                continue
            
            self.logger.info(f"Executing step: {step_name}")
            try:
                if step_func():
                    success_count += 1
                    self.logger.info(f"Step completed successfully: {step_name}")
                else:
                    self.logger.error(f"Step failed: {step_name}")
            except Exception as e:
                self.logger.error(f"Step failed with exception: {step_name} - {e}")
        
        self.logger.info("=" * 60)
        self.logger.info(f"Pipeline completed: {success_count}/{total_steps} steps successful")
        self.logger.info("=" * 60)
        
        return success_count == total_steps

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Dark Web Threat Intelligence Analyzer Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode (default)
  %(prog)s --batch                  # Batch mode (auto-yes to all prompts)
  %(prog)s --steps parse upload     # Run only specific steps
  %(prog)s --log-level DEBUG        # Enable debug logging
        """
    )
    
    parser.add_argument(
        "--batch", "-b",
        action="store_true",
        help="Run in batch mode (automatically answer 'yes' to all prompts)"
    )
    
    parser.add_argument(
        "--steps", "-s",
        nargs="+",
        choices=["parse", "upload", "cleanup"],
        help="Specify which steps to run (default: all steps)"
    )
    
    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Set logging level (default: from .env file or INFO)"
    )
    
    return parser

def main() -> int:
    """Main entry point for the pipeline."""
    try:
        # Parse command line arguments
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Initialize pipeline
        pipeline = LeakAnalyzerPipeline(
            batch_mode=args.batch,
            log_level=args.log_level
        )
        
        # Run pipeline
        success = pipeline.run_pipeline(steps=args.steps)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nPipeline interrupted by user.")
        return 130  # Standard exit code for SIGINT
    except PipelineError as e:
        print(f"Pipeline error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
