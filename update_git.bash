#!/bin/bash
#===============================================================================
#
# FILE: update_git.bash
#
# USAGE: update_git.bash [commit message]
#
# DESCRIPTION: This script updates a Git repository with the latest changes.
#              If a commit message is provided as an argument, it uses that.
#              Otherwise, it automatically uses a default message with the
#              list of changed files.
#              This script only runs if the 'run_python_test.bash' script
#              is successful.
#
# OPTIONS:
#    -h, --help      Display this help message
#    -v, --version   Display script version
#
# REQUIREMENTS: git, run_python_test.bash
#
# BUGS:
#
# NOTES:
#
# AUTHOR:
#    Mario Luz (ml), mario.mssl[at]gmail.com
#
# COMPANY:
#
# VERSION: 1.5  # Updated version
# CREATED: 2024-11-18 17:00:00
# REVISION: 2025-06-27 11:22:00 # Updated revision date
#===============================================================================

# Set script version
SCRIPT_VERSION="1.5"

# Display help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS] [commit message]

This script updates a Git repository with the latest changes.

OPTIONS:
  -h, --help      Display this help message
  -v, --version   Display script version

Examples:
  $0 "My commit message"
  $0 -m "My commit message"
  $0
EOF
}

# Display script version
show_version() {
  echo "$0 version $SCRIPT_VERSION"
}

# Get the commit message from the command line argument or prompt for one
commit_message=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    -v|--version)
      show_version
      exit 0
      ;;
    *)
      # This handles the commit message if it's the first non-option argument
      if [[ -z "$commit_message" ]]; then
        commit_message="$1"
      fi
      shift
      ;;
  esac
done

# Run the Python tests
echo "Running Python tests..."
./run_python_test.bash

# Check the exit code of the Python tests
if [[ $? -eq 0 ]]; then
  echo "Python tests passed."

  # Always add all changes, including new untracked files, to the staging area
  echo "Adding all changes (including new files) to staging area..."
  git add .

  # Check if there are any staged changes to commit
  if git diff --cached --quiet --exit-code; then
    echo "No changes to commit."
    # Even if no changes to commit, still pull and push for tags in case
    # there are remote updates or only tags need pushing.
    echo "Pulling latest changes from remote repository..."
    git pull origin main

    echo "Pushing (possibly just tags) to remote repository..."
    git push origin main
    git push origin --tags
    exit 0
  fi

  # Get the list of updated files (now including newly added files)
  updated_files=$(git diff --cached --name-only)

  # Use the default commit message if none is provided via argument
  if [[ -z "$commit_message" ]]; then
    commit_message="Updating files: $updated_files"
  fi

  echo "Committing with message: '$commit_message'"
  # Commit the changes
  git commit -m "$commit_message"

  # Pull the latest changes from the remote repository BEFORE pushing local commits
  # This helps avoid conflicts if others have pushed
  echo "Pulling latest changes from remote repository..."
  git pull origin main

  # Check for merge conflicts after pulling
  if [[ $(git status --porcelain | grep "^UU" | wc -l) -gt 0 ]]; then
      echo "!!! Merge conflicts detected after pulling. Please resolve them manually !!!"
      echo "Aborting push. Run 'git status' to see conflicted files."
      exit 1
  fi

  # Push the changes to the remote repository
  echo "Pushing changes to remote repository..."
  git push origin main

  # Push the tags to the remote repository
  echo "Pushing tags to remote repository..."
  git push origin --tags

else
  echo "Python tests failed. Aborting Git update."
  exit 1 # Exit with an error code
fi
