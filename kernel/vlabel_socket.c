/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 vLabel Project
 * All rights reserved.
 *
 * vLabel Socket Label Management
 *
 * Handles socket label lifecycle and access checks.
 * Socket labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_vlabel.h"

/*
 * Socket label lifecycle
 */

int
vlabel_socket_init_label(struct label *label, int flag)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(flag == M_WAITOK ? M_WAITOK : M_NOWAIT);
	if (vl == NULL)
		return (ENOMEM);
	SLOT_SET(label, vl);
	return (0);
}

void
vlabel_socket_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

void
vlabel_socket_copy_label(struct label *src, struct label *dest)
{
	struct vlabel_label *srcvl, *dstvl;

	if (src == NULL || dest == NULL)
		return;

	srcvl = SLOT(src);
	dstvl = SLOT(dest);

	if (srcvl != NULL && dstvl != NULL)
		vlabel_label_copy(srcvl, dstvl);
}

/*
 * Socket creation - inherit label from creating credential
 */
void
vlabel_socket_create(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct vlabel_label *credlabel, *slabel;

	if (cred == NULL || cred->cr_label == NULL || solabel == NULL)
		return;

	credlabel = SLOT(cred->cr_label);
	slabel = SLOT(solabel);

	if (credlabel != NULL && slabel != NULL)
		vlabel_label_copy(credlabel, slabel);
}

/*
 * New connection on listening socket - inherit label from parent
 */
void
vlabel_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{
	struct vlabel_label *oldlabel, *newlabel;

	if (oldsolabel == NULL || newsolabel == NULL)
		return;

	oldlabel = SLOT(oldsolabel);
	newlabel = SLOT(newsolabel);

	if (oldlabel != NULL && newlabel != NULL)
		vlabel_label_copy(oldlabel, newlabel);
}

/*
 * Socket access checks
 *
 * For socket operations, the subject is the process credential and
 * the object is the socket label. This allows rules like:
 *   deny connect type=untrusted -> *
 *   allow bind type=webserver -> *
 */

int
vlabel_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_ACCEPT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_BIND, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_CONNECT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_create(struct ucred *cred, int domain, int type,
    int protocol)
{

	/*
	 * Socket creation is always allowed - the socket inherits the
	 * creator's label. Access control happens at bind/connect/etc.
	 */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_LISTEN, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_RECEIVE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules */
	error = vlabel_rules_check(cred, subj, obj, VLABEL_OP_SEND, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
vlabel_socket_check_stat(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

	/* Stat is always allowed - not a security-relevant operation */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_socket_check_visible(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

	/* Visibility is always allowed - enforcing at other operations */
	VLABEL_CHECK_ENABLED();
	return (0);
}

int
vlabel_socket_check_poll(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

	/* Poll is always allowed - not a security-relevant operation */
	VLABEL_CHECK_ENABLED();
	return (0);
}

/*
 * Socketpeer label lifecycle
 *
 * The socketpeer label represents the remote end of a connection.
 * For Unix domain sockets, this is the connecting process's label.
 * For TCP connections, this can be set from incoming packets or
 * propagated from accept().
 *
 * This enables rules like:
 *   deny accept * -> type=untrusted   # reject connections from untrusted peers
 *   allow connect type=client -> type=server
 */

int
vlabel_socketpeer_init_label(struct label *label, int flag)
{
	struct vlabel_label *vl;

	vl = vlabel_label_alloc(flag == M_WAITOK ? M_WAITOK : M_NOWAIT);
	if (vl == NULL)
		return (ENOMEM);
	/* Peer labels default to empty (unlabeled) until set */
	SLOT_SET(label, vl);
	return (0);
}

void
vlabel_socketpeer_destroy_label(struct label *label)
{
	struct vlabel_label *vl;

	vl = SLOT(label);
	if (vl != NULL)
		vlabel_label_free(vl);
	SLOT_SET(label, NULL);
}

/*
 * Set peer label from incoming mbuf (network packet).
 *
 * This is called when a packet arrives and we need to set the peer
 * label from the mbuf's label. For IP-based sockets, the mbuf label
 * typically comes from the network layer (if labeled networking is used).
 *
 * For most use cases without labeled networking, this copies an empty label.
 */
void
vlabel_socketpeer_set_from_mbuf(struct mbuf *m, struct label *mlabel,
    struct socket *so, struct label *sopeerlabel)
{
	struct vlabel_label *mbuflabel, *peerlabel;

	if (mlabel == NULL || sopeerlabel == NULL)
		return;

	mbuflabel = SLOT(mlabel);
	peerlabel = SLOT(sopeerlabel);

	if (mbuflabel != NULL && peerlabel != NULL)
		vlabel_label_copy(mbuflabel, peerlabel);
}

/*
 * Set peer label from another socket (accept).
 *
 * When a connection is accepted, the new socket's peer label is set
 * from the connecting socket's label. This is the primary mechanism
 * for Unix domain socket peer labeling.
 *
 * For TCP accept(), oldso is the connecting socket and newso is the
 * newly accepted socket. The peer label of newso gets the label of oldso.
 */
void
vlabel_socketpeer_set_from_socket(struct socket *oldso,
    struct label *oldsolabel, struct socket *newso,
    struct label *newsopeerlabel)
{
	struct vlabel_label *oldlabel, *peerlabel;

	if (oldsolabel == NULL || newsopeerlabel == NULL)
		return;

	oldlabel = SLOT(oldsolabel);
	peerlabel = SLOT(newsopeerlabel);

	if (oldlabel != NULL && peerlabel != NULL)
		vlabel_label_copy(oldlabel, peerlabel);
}

/*
 * Check if a packet can be delivered to a socket.
 *
 * This hook is called when a network packet (mbuf) is about to be
 * delivered to a socket. It allows policies to filter incoming packets
 * based on their label (if labeled networking is in use) versus the
 * socket's label.
 *
 * This enables rules like:
 *   deny deliver type=external -> type=internal
 *   allow deliver type=trusted -> *
 *
 * Note: Without labeled networking (CIPSO, IPSEC with labels), the mbuf
 * label will typically be empty, so this hook is mostly useful when
 * combined with network labeling.
 */
int
vlabel_socket_check_deliver(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{
	struct vlabel_label *subj, *obj;
	int error;

	VLABEL_CHECK_ENABLED();

	/*
	 * Subject is the packet (mbuf) label - the incoming data.
	 * Object is the socket label - the destination.
	 */
	if (mlabel == NULL)
		return (0);
	subj = SLOT(mlabel);
	if (subj == NULL)
		subj = &vlabel_default_subject;

	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &vlabel_default_object;

	/* Evaluate rules - no credential available, packet delivery */
	error = vlabel_rules_check(NULL, subj, obj, VLABEL_OP_DELIVER, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && vlabel_mode == VLABEL_MODE_PERMISSIVE)
		return (0);

	return (error);
}
