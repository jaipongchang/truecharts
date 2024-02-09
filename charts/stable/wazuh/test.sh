#!/bin/bash

# Prompt user for input
read -p "Enter a value to hash: " input

# Use bcrypt to hash the input value
hashed_value=$(echo "$input" | base64)

# Output the hashed value
echo $hashed_value

