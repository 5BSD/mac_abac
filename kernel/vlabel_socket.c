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
