#!/bin/sh
# Test image only: synthetic password, never a real credential.
printf '%s\n' 'OK face smoke pinentry'
while IFS= read -r line; do
    case "$line" in
        GETPIN)
            printf '%s\n' 'GETPIN' >>/run/face-smoke/pinentry-events
            if [ "$(cat /run/face-smoke/pinentry)" = allow ]; then
                printf '%s\n' 'D rbw-e2e-password' 'OK'
            else
                printf '%s\n' 'ERR 83886179 Operation cancelled'
            fi
            ;;
        BYE) printf '%s\n' 'OK'; exit 0 ;;
        *) printf '%s\n' 'OK' ;;
    esac
done
