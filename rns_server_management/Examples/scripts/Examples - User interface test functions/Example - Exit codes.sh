#!/bin/bash


declare -A options=(
    ["Success"]=0
    ["General error"]=1
    ["Misuse of shell builtins"]=2
    ["Command invoked cannot execute"]=126
    ["Command not found"]=127
    ["Invalid argument to exit"]=128
    ["Terminated by Control-C"]=130
    ["General error condition"]=255
)

echo "Select an exit code:"
select option in "${!options[@]}"; do
    if [[ -n "$option" ]]; then
        selected_code="${options[$option]}"
        echo "Exiting with exit code $selected_code: $option."
        exit $selected_code
    else
        echo "Invalid choice. Exiting with exit code 1 (General error)."
        exit 1
    fi
done
