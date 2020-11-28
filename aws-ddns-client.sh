#!/bin/bash

HOST=$1
ALIAS=$2
BOTH="$2.$1"

# Check if we can use colors in the terminal.
if test -t 1; then
    ncolors=$(tput colors 2>/dev/null)
    if test -n "$ncolors" && test $ncolors -ge 8; then
        TEXT_BOLD="$(tput bold)"
        TEXT_RESET="$(tput sgr0)"
        TEXT_RED="$(tput setaf 1)"
        TEXT_GREEN="$(tput setaf 2)"
        TEXT_YELLOW="$(tput setaf 3)"
    fi
fi

maxLineLength() {
    echo -n "$1" | awk '{ print length }' | sort -n | tail -1
}

minLineLength() {
    echo -n "$1" | awk '{ print length }' | sort -n | head -1
}

printTable() {
    NAMES=""
    VALUES=""
    
    for i; do
        if [ -z "$NAMES" ]; then
            NAMES="$i"
            VALUES="${!i}"
        else
            NAMES="$NAMES"$'\n'"$i"
            VALUES="$VALUES"$'\n'"${!i}"
        fi
    done
    
    MAX_VAR_NAME_LEN="$(maxLineLength """$NAMES""")"
    MIN_VAR_NAME_LEN="$(minLineLength """$NAMES""")"
    MAX_VAR_VALUE_LEN="$(maxLineLength """$VALUES""")"
    MIN_VAR_VALUE_LEN="$(minLineLength """$VALUES""")"
    DIVIDER_LEN="$(("""$MAX_VAR_NAME_LEN""" + """$MAX_VAR_VALUE_LEN""" + 6))"
    
    if [ "$DIVIDER_LEN" -gt 0 ]; then
        DIVIDER="$(head -c """$DIVIDER_LEN""" < /dev/zero | tr '\0' '-')"
    fi
    
    echo ".$DIVIDER."
    for i; do
        VAR_NAME="$i"
        VAR_VALUE="${!i}"
        VAR_NAME_LEN="$(echo -n """$VAR_NAME""" | wc -m)"
        VAR_VALUE_LEN="$(echo -n """$VAR_VALUE""" | wc -m)"
        VAR_NAME_PAD_LEN="$(("""$MAX_VAR_NAME_LEN""" - """$VAR_NAME_LEN""" + 1))"
        VAR_VALUE_PAD_LEN="$(("""$MAX_VAR_VALUE_LEN""" - """$VAR_VALUE_LEN""" + 1))"
        
        if [ "$VAR_NAME_PAD_LEN" -gt 0 ]; then
            VAR_NAME_PAD="$(head -c """$VAR_NAME_PAD_LEN""" < /dev/zero | tr '\0' ' ')"
        fi
        
        if [ "$VAR_VALUE_PAD_LEN" -gt 0 ]; then
            VAR_VALUE_PAD="$(head -c """$VAR_VALUE_PAD_LEN""" < /dev/zero | tr '\0' ' ')"
        fi
        
        printf "| %s%s: %s%s%s%s |\n" \
            "$VAR_NAME_PAD" \
            "$VAR_NAME" \
            "$TEXT_BOLD" \
            "$VAR_VALUE" \
            "$TEXT_RESET" \
            "$VAR_VALUE_PAD"
    done
    echo "'$DIVIDER'"
}

printAliasInfo() {
    RESPONSE="$(getAliasInfo ""$1"" ""$2"")"
    
    IP="$(getJSONPropertyValue """$RESPONSE""" ""address"")"
    FAMILY="$(getJSONPropertyValue """$RESPONSE""" ""family"")"
    CNAME="$(getJSONPropertyValue """$RESPONSE""" ""cname"")"
    CREATED="$(getJSONPropertyValue """$RESPONSE""" ""created"")"
    UPDATED="$(getJSONPropertyValue """$RESPONSE""" ""updated"")"

    printTable "IP" "FAMILY" "CNAME" "CREATED" "UPDATED"
}

getJSONPropertyValue() {
    echo "$1" | \
        # Find the property name and value, separated by ":".
        # E.g. "something":0 or "something":"something" or "something":true, etc.
        grep -oP "\"$2\":(\"(\\\\.|[^\\\"])*\"|((\-?[0-9]+(\.[0-9]+)?)|true|false))" | \
        # Get everything after first ":" and on.
        cut -d":" -f2- | \
        # Remove surround quotes (if they exist).
        sed 's/^\(\"\)\(.*\)\1$/\2/'
}

getAliasInfo () {
    curl -X GET -s "https://$1?alias=$2"
}

# Generate RSA 4096 private key if one doesn't already exist.
if [ ! -f "$BOTH.pem" ]; then
    printf "%s%s%s\n" $COLOR_YELLOW "RSA private key not found; generating one now..." $TEXT_RESET
    openssl genrsa -out "$BOTH.pem" 4096
fi

# Generate matching RSA public from private key if one doesn't already exist.
if [ ! -f "$BOTH.pub" ]; then
    printf "%s%s%s\n" $COLOR_YELLOW "RSA public key not found; generating one now..." $TEXT_RESET
    openssl rsa -in "$BOTH.pem" -out "$BOTH.pub" -outform PEM -pubout
fi

echo "Checking if alias already exists..."

RESPONSE="$(getAliasInfo ""$HOST"" ""$ALIAS"")"
EXISTS=0 && [ "$(getJSONPropertyValue """$RESPONSE""" ""ok"")" = "true" ] && EXISTS=1

# If alias does not exist, claim it, else if alias does exist, update it.
if [ "$EXISTS" -eq 0 ]; then
    echo "Alias does not exist; claiming alias now..."
    
    # PUB_KEY="$(sed -z 's/\n/\\n/g;s/\\n$//' ""$BOTH.pub"")"
    PUB_KEY="$(cat ""$BOTH.pub"")"
    PAYLOAD="{\"alias\":\"""$ALIAS""\",\"publicKey\":\"""$PUB_KEY""\"}"
    
    # Send the claim request.
    RESPONSE="$(curl -s -X POST ""https://"""$HOST""""" -H """Content-Type: application/json""" -d """$PAYLOAD""")"
    
    SECRET="$(getJSONPropertyValue ""$RESPONSE"" ""secret"")"
    if [ -z $SECRET ]; then
        printf "%s%s%s\n" $COLOR_RED "Error when claiming alias: $RESPONSE" $TEXT_RESET
        exit 1
    fi
    
    echo "Writing secret to \"""$BOTH"".secret.txt\""
    echo -n "$SECRET" > "$BOTH.secret.txt"
    
    printf "%s%s%s\n" $COLOR_GREEN "Successfully claimed alias!" $TEXT_RESET
    echo "Waiting 5s for record propogation."
    sleep 5
elif [ "$EXISTS" -eq 1 ]; then
    echo "Alias exists; updating alias now..."
    
    SECRET_FILE="$BOTH.secret.txt"
    if [ ! -f "$SECRET_FILE" ]; then
        printf "%s%s%s\n" $COLOR_RED "Error when updating alias: Cannot find \"$SECRET_FILE\"." $TEXT_RESET
        exit 1
    fi
    
    SECRET="$(cat ""$SECRET_FILE"" | tr -d ""\n"")"
    UTC_DATE="$(date +%s000)"
    SIGNATURE="$(echo -n ""{\"alias\":\"""$ALIAS""\",\"now\":\"""$UTC_DATE""\",\"secret\":\"""$SECRET""\"}"" | openssl dgst -sha256 -sign """""$BOTH""".pem"" -binary | base64)"
    PAYLOAD="{\"alias\":\"""$ALIAS""\",\"signature\":\"""$SIGNATURE""\"}"
    
    # Send the update request.
    RESPONSE="$(curl -s -X POST ""https://"""$HOST""""" -H """Content-Type: application/json""" -d """$PAYLOAD""")"
    
    printf "%s%s%s\n" $COLOR_GREEN "Successfully updated alias!" $TEXT_RESET
    echo "Waiting 5s for record propogation."
    sleep 5
fi

# Get alias info using the API.
# NOTE: You can also retrieve the alias using dnsutils:
# $ nslookup "https://$HOST?alias=$ALIAS"
echo "Retrieving alias info..."
printAliasInfo "$HOST" "$ALIAS"

exit 0