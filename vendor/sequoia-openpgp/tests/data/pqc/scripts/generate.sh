#!/usr/bin/bash

###
### generate artifacts
### USAGE: bash generate.sh $TARGET_DIRECTORY
### -
### Make sure that both `rsop` and `gosop` are
### either in your $PATH or are accessible via
### the environment variables $RSOP and $GOSOP
### respectively.
###

set -e

WORKDIR=$1

usage() { # message_string
  echo "Error: " $1
  echo
  sed -n 's/^### //p' $0 | fmt
  exit 1
}

if [ "$WORKDIR" == "" ] ; then
  usage "target directory missing"
fi

if ! [ -d $WORKDIR ] ; then
  mkdir -p $WORKDIR
fi

if [ -z $RSOP ] ; then
  RSOP=$(which rsop)
fi

if [ -z $GOSOP ] ; then
  GOSOP=$(which gosop)
fi

if [ -z $RSOP ] ; then
  usage "Cannot find rsop binary"
fi

if [ -z $GOSOP ] ; then
  usage "Cannot find gosop binary"
fi

USER_ALICE="Alice <alice@example.com>"
USER_BOB="Bob <bob@example.com>"
MESSAGE="Hello World"

#
# RSOP
#
echo "Using $RSOP for rsop"

# rsop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-08-v4-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-mldsa65ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-mldsa87ed448-mlkem1024x448
draft-ietf-openpgp-pqc-08-v6-slhdsashake128s-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-slhdsashake128f-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-slhdsashake256s-mlkem1024x448"

SUBDIRECTORY="rpgp"

for PROFILE in $PROFILES ; do
  echo -n "rsop: Profile $PROFILE..."
  mkdir -p $WORKDIR/$SUBDIRECTORY

  echo -n " alice"
  $RSOP generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp | $RSOP extract-cert > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_pk.pgp

  echo -n " bob"
  $RSOP generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_sk.pgp | $RSOP extract-cert > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_pk.pgp

  echo -n " encrypt"
  echo $MESSAGE | $RSOP encrypt --sign-with $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_pk.pgp > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_message.pgp

  echo -n " sign-detached"
  echo $MESSAGE | $RSOP sign $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_detached_sig.pgp
  echo " done."
done

#
# GOSOP
#
echo "Using $GOSOP for gosop"

# gosop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-09
draft-ietf-openpgp-pqc-09-high-security"

SUBDIRECTORY="gopenpgp"

for PROFILE in $PROFILES ; do
  echo -n "gosop: Profile $PROFILE..."
  mkdir -p $WORKDIR/$SUBDIRECTORY

  echo -n " alice"
  $GOSOP generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp | $GOSOP extract-cert > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_pk.pgp

  echo -n " bob"
  $GOSOP generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_sk.pgp | $GOSOP extract-cert > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_pk.pgp

  echo -n " encrypt"
  echo $MESSAGE | $GOSOP encrypt --sign-with $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_pk.pgp > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_message.pgp

  echo -n " sign-detached"
  echo $MESSAGE | $GOSOP sign $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_detached_sig.pgp
  echo " done."
done

echo "Results stored in $WORKDIR"
