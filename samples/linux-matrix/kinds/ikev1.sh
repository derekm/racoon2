#!/bin/sh
# kinds/ikev1.sh — expected skip vs strongSwan 5.9.13 msg5.
kind_ikev1() {
	log "SKIP $1: IKEv1 msg5 vs strongSwan 5.9.13 is not a racoon2 bug"
	return 0
}
