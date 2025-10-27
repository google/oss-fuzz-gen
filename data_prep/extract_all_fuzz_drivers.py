#!/usr/bin/env python3
"""
Extract all human-written fuzz drivers from OSS-Fuzz projects.
Download from Google Cloud Storage bucket oss-fuzz-llm-public.
"""

# Configure logging.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Google Cloud Storage configuration.
OSS_FUZZ_BUCKET = 'oss-fuzz-llm-public'
HUMAN_TARGETS_PREFIX = 'human_written_targets'


def list_all_projects_in_bucket() -> Set[str]:
    """List all projects in the bucket that contain fuzz drivers."""
    logger.info(f'Scanning bucket {OSS_FUZZ_BUCKET} for projects...')
    
    try:
        storage_client = storage.Client.create_anonymous_client()
        bucket = storage_client.bucket(OSS_FUZZ_BUCKET)
        
        # List all blobs starting with human_written_targets/.
        blobs = bucket.list_blobs(prefix=HUMAN_TARGETS_PREFIX + '/')
        
        projects = set()
        for blob in blobs:
            # Extract project name from blob name.
            # Format: human_written_targets/project_name/file_path.
            parts = blob.name.split('/')
            if len(parts) >= 2:
                project_name = parts[1]
                if project_name:  # Ensure project name is not empty.
                    projects.add(project_name)
        
        logger.info(f'Found {len(projects)} projects with fuzz drivers.')
        return projects
    
    except Exception as e:
        logger.error(f'Failed to scan bucket: {e}')
        return set()


def download_project_fuzz_drivers(project_name: str, output_dir: str) -> bool:
    """
    Download all fuzz drivers for the specified project.
    
    Args:
        project_name: Project name.
        output_dir: Output root directory.
    
    Returns:
        Whether the download was successful.
    """
    try:
        # Create project-specific output directory.
        project_output_dir = os.path.join(output_dir, project_name)
        os.makedirs(project_output_dir, exist_ok=True)
        
        # Connect to Google Cloud Storage.
        storage_client = storage.Client.create_anonymous_client()
        bucket = storage_client.bucket(OSS_FUZZ_BUCKET)
        
        # Build project storage prefix.
        project_prefix = f'{HUMAN_TARGETS_PREFIX}/{project_name}/'
        
        # List all files in the project.
        blobs = bucket.list_blobs(prefix=project_prefix)
        
        file_count = 0
        for blob in blobs:
            # Get relative path (remove project prefix).
            relative_path = blob.name.replace(f'{project_prefix}', '', 1)
            
            # Skip empty paths (folder itself).
            if not relative_path:
                continue
            
            # Build local file path.
            local_file_path = os.path.join(project_output_dir, relative_path)
            
            # Create necessary subdirectories.
            local_dir = os.path.dirname(local_file_path)
            if local_dir:
                os.makedirs(local_dir, exist_ok=True)
            
            # Download file.
            blob.download_to_filename(local_file_path)
            file_count += 1
            logger.debug(f'  Downloaded: {relative_path}')
        
        if file_count > 0:
            logger.info(f'✓ {project_name}: Successfully downloaded {file_count} files')
            return True
        else:
            logger.warning(f'✗ {project_name}: No files found')
            return False
            
    except Exception as e:
        logger.error(f'✗ {project_name}: Download failed - {e}')
        return False


def download_all_projects(projects: List[str], output_dir: str, max_workers: int = 10):
    """
    Concurrent download of all project fuzz drivers.
    
    Args:
        projects: Project name list.
        output_dir: Output root directory.
        max_workers: Maximum number of concurrent threads.
    """
    logger.info(f'Starting download of {len(projects)} projects fuzz drivers...')
    logger.info(f'Output directory: {output_dir}')
    logger.info(f'Concurrent threads: {max_workers}')
    
    success_count = 0
    fail_count = 0
    
    # Use thread pool to download concurrently.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all download tasks.
        future_to_project = {
            executor.submit(download_project_fuzz_drivers, project, output_dir): project
            for project in projects
        }
        
        # Process completed tasks.
        for future in as_completed(future_to_project):
            project = future_to_project[future]
            try:
                if future.result():
                    success_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                logger.error(f'{project} processing exception: {e}')
                fail_count += 1
    
    logger.info('=' * 60)
    logger.info(f'Download completed!')
    logger.info(f'Success: {success_count} projects')
    logger.info(f'Failure: {fail_count} projects')
    logger.info(f'Total: {len(projects)} projects')
    logger.info(f'Output location: {os.path.abspath(output_dir)}')


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Extract all fuzz drivers from OSS-Fuzz projects from Google Cloud Storage.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Download all projects to default directory
  python extract_all_fuzz_drivers.py
  
  # Specify output directory
  python extract_all_fuzz_drivers.py -o /path/to/output
  
  # Only download specific projects
  python extract_all_fuzz_drivers.py -p libxml2 zlib
  
  # Adjust number of concurrent threads
  python extract_all_fuzz_drivers.py -w 20
        """
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        type=str,
        default='./extracted_fuzz_drivers',
        help='Output directory (default: ./extracted_fuzz_drivers)'
    )
    
    parser.add_argument(
        '-p', '--projects',
        type=str,
        nargs='+',
        help='List of projects to download (default: all projects)'
    )
    
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed logs'
    )
    
    parser.add_argument(
        '--list-only',
        action='store_true',
        help='List only available projects, do not download'
    )
    
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_arguments()
    
    # Set logging level.
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Get project list.
    if args.projects:
        # Use user-specified project list.
        projects = args.projects
        logger.info(f'Using user-specified {len(projects)} projects')
    else:
        # Automatically scan all projects in the bucket.
        projects = list_all_projects_in_bucket()
        if not projects:
            logger.error('No projects found, exiting')
            return 1
    
    # Sort project list.
    projects = sorted(projects)
    
    # If only listing projects, do not download.
    if args.list_only:
        logger.info('\nAvailable projects list:')
        for i, project in enumerate(projects, 1):
            print(f'{i:4d}. {project}')
        logger.info(f'\nTotal: {len(projects)} projects')
        return 0
    
    # Create output directory.
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # Download all projects.
    download_all_projects(projects, output_dir, args.workers)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

