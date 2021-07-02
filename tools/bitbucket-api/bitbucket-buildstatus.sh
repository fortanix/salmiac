RETRIES=20
WAIT_SECONDS=30

# Exchange an oath2 key/secret pair for an access token that can be used with the bitbucket api
# Key and secret can be issued from your bitbucket account
BitBucketGetAccessToken () {

    if [ $# -ne 2 ]
    then
        echo "usage ${FUNCNAME[0]} key secret"
        exit 1
    fi

    local KEY=$1
    local SECRET=$2

    local URL="https://bitbucket.org/site/oauth2/access_token"

    local TRY=0
    local CREDS=""
    until CREDS=$(curl -sX POST -u "${KEY}:${SECRET}" $URL -d grant_type=client_credentials); do
        ((TRY++)) && ((TRY==RETRIES)) && echo "BitBucketAPI: failed to get token after $RETRIES attemps, giving up" && exit 111

        echo "BitBucketAPI: failed to get token, attempt(${TRY}/${RETRIES}) retrying in ${WAIT_SECONDS}"
        sleep ${WAIT_SECONDS}
    done
    TOKEN=$(echo $CREDS | jq .access_token)
}

# Set or update a build status on a specific commit hash
BitBucketSetStatus () {

    if [ $# -ne 7 ]
    then
        echo "usage ${FUNCNAME[0]} status repo_name commit_hash access_token test_name test_link test_description"
        exit 1
    fi

    local STATUS=$1
    local REPO_NAME=$2
    local COMMIT_HASH=$3
    local TOKEN=$4
    local TEST_NAME=$5
    local TEST_LINK=$6
    local TEST_DESCRIPTION=$7

    local URL="https://api.bitbucket.org/2.0/repositories/${REPO_NAME}/commit/${COMMIT_HASH}/statuses/build/?access_token=${TOKEN}"
    local TRY=0

    until curl -sX POST $URL -H "Content-Type: application/json" -d'
{
    "state": "'"${STATUS}"'",
    "key": "'"${TEST_NAME}"'",
    "name": "'"${TEST_NAME}"'",
    "url": "'"${TEST_LINK}"'",
    "description": "'"${TEST_DESCRIPTION}"'"
}
'
    do
        ((TRY++)) && ((TRY==RETRIES)) && echo "BitBucketAPI: failed to post status fater $RETRIES attemps, giving up" && exit 111

        echo "BitBucketAPI: failed to post status, attempt(${TRY}/${RETRIES}) retrying in ${WAIT_SECONDS}"
        sleep ${WAIT_SECONDS}
    done
}
