#!/bin/bash

# SpamAssassin Auto-Learn Script
# Processes spam messages from Maildir/.SPAM/cur folder
# Runs sa-learn --spam on each message, then deletes it
# Logs summary to syslog

# Configuration
MAILDIR_BASE="/mail/domains"  # Base path for domain/user structure
SPAM_DIR="Maildir/.SPAM/cur"
VPOPMAIL_USER="vpopmail"
VPOPMAIL_GROUP="vchkpw"
SPAMD_USER="qscand"
LOCK_FILE="/var/run/spam-autolearn.lock"
LOG_TAG="spam-autolearn"

# Function to log messages to syslog
log_message() {
    local priority="$1"
    local message="$2"
    logger -t "$LOG_TAG" -p "mail.$priority" "$message"
}

# Function to create SPAM folder structure if missing
create_spam_folder() {
    local maildir_path="$1"
    local spam_base_dir="$maildir_path/.SPAM"
    
    if [ ! -d "$spam_base_dir" ]; then
        log_message "info" "Creating missing SPAM folder structure: $spam_base_dir"
        
        # Create the main .SPAM directory and subdirectories
        mkdir -p "$spam_base_dir"/{new,cur,tmp}
        
        # Set proper ownership
        chown -R "$VPOPMAIL_USER:$VPOPMAIL_GROUP" "$spam_base_dir"
        
        # Set proper permissions (typically 700 for Maildir folders)
        chmod 700 "$spam_base_dir"
        chmod 700 "$spam_base_dir"/{new,cur,tmp}
        
        log_message "info" "Created SPAM folder structure with vpopmail.vchkpw ownership: $spam_base_dir"
        return 0
    fi
    return 1
}
cleanup() {
    rm -f "$LOCK_FILE"
    log_message "info" "Script finished"
}

# Set up trap for cleanup
trap cleanup EXIT

# Check if script is already running
if [ -f "$LOCK_FILE" ]; then
    log_message "warning" "Script already running (lock file exists)"
    exit 1
fi

# Create lock file
echo $$ > "$LOCK_FILE"

log_message "info" "Starting spam auto-learn process"

# Initialize counters
total_processed=0
total_learned=0
total_errors=0
total_deleted=0

# Function to clean up lock file on exit
# Function to process a single user's spam folder
process_user_spam() {
    local user_maildir="$1"
    local domain="$2"
    local username="$3"
    local user_spam_dir="$user_maildir/.SPAM/cur"
    
    # Check if SPAM folder exists, create if missing
#    if [ ! -d "$user_maildir/.SPAM" ]; then
#        create_spam_folder "$user_maildir"
#    fi
    
    # If SPAM/cur still doesn't exist after creation attempt, skip
    if [ ! -d "$user_spam_dir" ]; then
        log_message "error" "Failed to create or access SPAM folder for $username@$domain"
        return 0
    fi
    
    local user_processed=0
    local user_learned=0
    local user_errors=0
    local user_deleted=0
    
    # Process each message in the spam folder
    for message_file in "$user_spam_dir"/*; do
        # Skip if no files match the pattern or if it's just the glob pattern
        if [ ! -f "$message_file" ] || [ "$message_file" = "$user_spam_dir/*" ]; then
            continue
        fi
        
        ((user_processed++))
        ((total_processed++))
        
        # Run sa-learn on the message as the vpopmail user
        if sa-learn -u "$SPAMD_USER" --spam "$message_file" >/dev/null 2>&1; then
            ((user_learned++))
            ((total_learned++))
            
            # Delete the message after successful learning
            if rm "$message_file" 2>/dev/null; then
                ((user_deleted++))
                ((total_deleted++))
            else
                log_message "warning" "Failed to delete message: $message_file"
            fi
        else
            ((user_errors++))
            ((total_errors++))
            log_message "warning" "Failed to learn from message: $message_file (user: $username@$domain)"
        fi
    done
    
    # Log user summary if any messages were processed
    if [ $user_processed -gt 0 ]; then
        log_message "info" "User $username@$domain: processed=$user_processed, learned=$user_learned, deleted=$user_deleted, errors=$user_errors"
    fi
}

# Find all domain/user combinations and process their spam folders
if [ -d "$MAILDIR_BASE" ]; then
    total_domains=0
    total_users=0
    
    # Iterate through each domain
    for domain_dir in "$MAILDIR_BASE"/*; do
        if [ ! -d "$domain_dir" ]; then
            continue
        fi
        
        domain_name=$(basename "$domain_dir")
        domain_users=0
        ((total_domains++))
        
        log_message "debug" "Processing domain: $domain_name"
        
        # Iterate through each user in the domain
        for user_dir in "$domain_dir"/*; do
            if [ ! -d "$user_dir" ]; then
                continue
            fi
            
            username=$(basename "$user_dir")
            maildir_path="$user_dir/Maildir"
            
            # Check if this is a valid Maildir structure
            if [ -d "$maildir_path" ]; then
                ((domain_users++))
                ((total_users++))
                
                log_message "debug" "Processing user: $username@$domain_name"
                process_user_spam "$maildir_path" "$domain_name" "$username"
            else
                log_message "debug" "Skipping $user_dir - no Maildir found"
            fi
        done
        
        if [ $domain_users -gt 0 ]; then
            log_message "info" "Domain $domain_name: processed $domain_users users"
        fi
    done
    
    log_message "info" "Processed $total_users users across $total_domains domains"
else
    log_message "error" "Maildir base directory not found: $MAILDIR_BASE"
    exit 1
fi

# Log final summary
if [ $total_processed -eq 0 ]; then
    log_message "info" "No spam messages found to process"
else
    log_message "info" "SUMMARY: Total processed=$total_processed, learned=$total_learned, deleted=$total_deleted, errors=$total_errors"
fi

# Additional check for SpamAssassin database sync
if [ $total_learned -gt 0 ]; then
    log_message "info" "Running sa-learn --sync to update SpamAssassin database"
    if sa-learn -u "$SPAMD_USER" --sync >/dev/null 2>&1; then
        log_message "info" "SpamAssassin database sync completed successfully"
    else
        log_message "warning" "SpamAssassin database sync failed"
    fi
fi

exit 0