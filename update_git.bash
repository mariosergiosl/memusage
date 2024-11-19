#!/bin/bash
#
# This script updates a Git repository with the latest changes.
#
# Usage: ./update_git.sh [commit message]
#
# If no commit message is provided, the script will prompt for one.
#

# Check if there are uncommitted changes
if ! git diff-index --quiet HEAD --; then
  # Add all changes to the staging area
  git add .

  # Get the commit message from the command line argument or prompt for one
  if [[ -n "$1" ]]; then
    mensagem="$1"
  else
    read -p "Enter the commit message: " mensagem
  fi

  # Commit the changes
  git commit -m "$mensagem"

  # Push the changes to the remote repository
  git push origin main
else
  echo "No changes to commit."
fi
