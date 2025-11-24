"""
MRT File Downloader Module.

Handles automatic downloading and caching of MRT files from RIPE RIS.
"""

import os
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class MRTDownloader:
    """
    Downloads and manages MRT files from RIPE RIS.
    """

    DEFAULT_DOWNLOAD_URL = "https://data.ris.ripe.net/rrc00/latest-bview.gz"
    DEFAULT_CACHE_DIR = "data/mrt"
    CACHE_VALIDITY_DAYS = 7  # Consider cached files valid for 7 days

    def __init__(
        self,
        download_url: Optional[str] = None,
        cache_dir: Optional[str] = None
    ):
        """
        Initialize MRT downloader.

        Args:
            download_url: URL to download MRT file from
            cache_dir: Directory to cache downloaded files
        """
        self.download_url = download_url or self.DEFAULT_DOWNLOAD_URL
        self.cache_dir = Path(cache_dir or self.DEFAULT_CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cached_file_path(self) -> Path:
        """Get path to the cached MRT file."""
        filename = os.path.basename(self.download_url)
        return self.cache_dir / filename

    def is_cache_valid(self) -> bool:
        """
        Check if cached file exists and is recent enough.

        Returns:
            True if cache is valid
        """
        cached_file = self.get_cached_file_path()

        if not cached_file.exists():
            return False

        # Check file age
        file_age = datetime.now() - datetime.fromtimestamp(cached_file.stat().st_mtime)
        if file_age > timedelta(days=self.CACHE_VALIDITY_DAYS):
            logger.info(f"Cached MRT file is {file_age.days} days old (max: {self.CACHE_VALIDITY_DAYS})")
            return False

        # Check file size (should be at least 10MB)
        file_size = cached_file.stat().st_size
        if file_size < 10 * 1024 * 1024:  # 10MB
            logger.warning(f"Cached MRT file is too small: {file_size} bytes")
            return False

        logger.info(f"Using valid cached MRT file: {cached_file} ({file_size / (1024*1024):.2f} MB)")
        return True

    def download_mrt_file(self, force: bool = False) -> Optional[str]:
        """
        Download MRT file from RIPE RIS.

        Args:
            force: Force download even if cache is valid

        Returns:
            Path to downloaded file, or None on failure
        """
        cached_file = self.get_cached_file_path()

        # Check cache first
        if not force and self.is_cache_valid():
            return str(cached_file)

        logger.info(f"Downloading MRT file from: {self.download_url}")
        temp_file = cached_file.with_suffix('.tmp')

        try:
            # Download with progress
            def reporthook(block_num, block_size, total_size):
                if total_size > 0:
                    percent = min(100, block_num * block_size * 100 / total_size)
                    if block_num % 100 == 0:  # Log every 100 blocks
                        downloaded = block_num * block_size / (1024 * 1024)
                        total = total_size / (1024 * 1024)
                        logger.info(f"Downloading: {downloaded:.2f} MB / {total:.2f} MB ({percent:.1f}%)")

            urllib.request.urlretrieve(
                self.download_url,
                temp_file,
                reporthook=reporthook
            )

            # Move temp file to final location
            temp_file.rename(cached_file)

            file_size = cached_file.stat().st_size
            logger.info(f"Successfully downloaded MRT file: {cached_file} ({file_size / (1024*1024):.2f} MB)")

            return str(cached_file)

        except urllib.error.URLError as e:
            logger.error(f"Failed to download MRT file: {e}")
            if temp_file.exists():
                temp_file.unlink()
            return None

        except Exception as e:
            logger.error(f"Unexpected error downloading MRT file: {e}")
            if temp_file.exists():
                temp_file.unlink()
            return None

    def get_or_download_mrt_file(self, force: bool = False) -> Optional[str]:
        """
        Get MRT file path, downloading if necessary.

        Args:
            force: Force download even if cache is valid

        Returns:
            Path to MRT file, or None on failure
        """
        if not force and self.is_cache_valid():
            return str(self.get_cached_file_path())

        return self.download_mrt_file(force=force)

    def cleanup_old_files(self, keep_latest: int = 1):
        """
        Clean up old MRT files, keeping only the latest N files.

        Args:
            keep_latest: Number of recent files to keep
        """
        try:
            # Get all MRT files in cache directory
            mrt_files = list(self.cache_dir.glob("*.gz")) + list(self.cache_dir.glob("*.bz2"))

            if len(mrt_files) <= keep_latest:
                return

            # Sort by modification time (newest first)
            mrt_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

            # Remove old files
            for old_file in mrt_files[keep_latest:]:
                logger.info(f"Removing old MRT file: {old_file}")
                old_file.unlink()

        except Exception as e:
            logger.error(f"Error cleaning up old MRT files: {e}")


def ensure_mrt_file(
    mrt_file_path: Optional[str] = None,
    download_url: Optional[str] = None,
    auto_download: bool = True
) -> Optional[str]:
    """
    Ensure MRT file is available, downloading if necessary.

    Args:
        mrt_file_path: Path to MRT file (checks if exists)
        download_url: URL to download from
        auto_download: Whether to auto-download if file doesn't exist

    Returns:
        Path to MRT file, or None if unavailable
    """
    # If path is provided and exists, use it
    if mrt_file_path and os.path.exists(mrt_file_path):
        logger.info(f"Using existing MRT file: {mrt_file_path}")
        return mrt_file_path

    # If auto-download is disabled, return None
    if not auto_download:
        logger.warning("MRT file not found and auto-download is disabled")
        return None

    # Try to download
    logger.info("MRT file not found, attempting to download...")
    downloader = MRTDownloader(download_url=download_url)
    return downloader.get_or_download_mrt_file()


# Convenience function for CLI/startup
def download_mrt_on_startup():
    """
    Download MRT file on application startup if configured.

    Uses environment variables:
    - AUTO_DOWNLOAD_MRT: Enable auto-download (default: false)
    - MRT_DOWNLOAD_URL: URL to download from
    - MRT_FILE_PATH: Path to store downloaded file
    """
    auto_download = os.environ.get('AUTO_DOWNLOAD_MRT', 'false').lower() == 'true'

    if not auto_download:
        logger.info("MRT auto-download disabled")
        return

    download_url = os.environ.get('MRT_DOWNLOAD_URL')
    cache_dir = os.path.dirname(os.environ.get('MRT_FILE_PATH', 'data/mrt/latest-bview.gz'))

    logger.info("Checking MRT file on startup...")
    downloader = MRTDownloader(download_url=download_url, cache_dir=cache_dir)
    result = downloader.get_or_download_mrt_file()

    if result:
        logger.info(f"MRT file ready: {result}")
        # Clean up old files
        downloader.cleanup_old_files(keep_latest=2)
    else:
        logger.warning("Failed to ensure MRT file availability")
