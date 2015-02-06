void hurl_resolve(HURLDomain *domain) {
	struct addrinfo *resolver_result, *resolver_answer, resolver_hints;
	int resolver_retval, i;
	char address_str[INET6_ADDRSTRLEN];

	/* Initialize resolvers hints (REQUIRED) */
	memset(&resolver_hints, 0, sizeof(struct addrinfo));
	resolver_hints.ai_family = AF_UNSPEC;
	resolver_hints.ai_socktype = SOCK_STREAM;
	resolver_hints.ai_flags = AI_PASSIVE;
	resolver_hints.ai_protocol = 0;
	resolver_hints.ai_canonname = NULL;
	resolver_hints.ai_addr = NULL;
	resolver_hints.ai_next = NULL;

	/* Resolve domain name */
	if ((resolver_retval = getaddrinfo(domain->domain, NULL, &resolver_hints, &resolver_result)) == 0) {
		/* Count number of answers. */
		domain->nrof_addresses = 0;
		for (resolver_answer = resolver_result; resolver_answer != NULL; resolver_answer = resolver_answer->ai_next) {
			domain->nrof_addresses++;
		}
		hurl_debug(__func__, "[ %s ] Number of addresses: %d", domain->domain, domain->nrof_addresses);
		if (domain->nrof_addresses > 0) {

			/* Allocate pointer space. */
			if ((domain->addresses = calloc(domain->nrof_addresses, sizeof(struct sockaddr *))) == NULL) {
				/* Out of memory. */
				domain->dns_state = DNS_STATE_ERROR;
				return;
			}
			i = 0;
			for (resolver_answer = resolver_result; resolver_answer != NULL; resolver_answer = resolver_answer->ai_next) {
				if ((domain->addresses[i] = calloc(1, sizeof(struct sockaddr))) == NULL) {
					/* Out of memory. */
					domain->dns_state = DNS_STATE_ERROR;
					return;
				}
				memcpy(domain->addresses[i], resolver_answer->ai_addr, sizeof(struct sockaddr));

				if (domain->addresses[i]->sa_family == AF_INET) {
					inet_ntop(AF_INET, &((struct sockaddr_in *) domain->addresses[i])->sin_addr, address_str, INET6_ADDRSTRLEN);
					hurl_debug(__func__, "[ %s ] %s", domain->domain, address_str);
				} else {
					inet_ntop(AF_INET6, &((struct sockaddr_in6 *) domain->addresses[i])->sin6_addr, address_str, INET6_ADDRSTRLEN);
					hurl_debug(__func__, "[ %s ] %s", domain->domain, address_str);
				}
				i++;
			}
			freeaddrinfo(resolver_result);
			domain->dns_state = DNS_STATE_RESOLVED;
		} else {
			domain->dns_state = DNS_STATE_ERROR;
		}
	} else {
		/* Resolution failed. */
		hurl_debug(__func__, "[ %s ] Resolver error: %s", domain->domain, gai_strerror(resolver_retval));
		domain->dns_state = DNS_STATE_ERROR;
	}
}

/* Warning: labels array size should always be 127 */
unsigned char split_domain_name(char *name, char *labels[]) {
	unsigned char nrof_labels = 0;
	char *name_tmp, *name_split_ptr, *label;
	name_tmp = strdup(name);
	while ((label = strtok_r(name_tmp, ".", &name_split_ptr)) != NULL) {
		if (nrof_labels == 127) {
			hurl_debug(__func__, "WARNING: Max labels reached.");
			break;
		}
		labels[nrof_labels] = strdup(label);
		if (name_tmp != NULL)
			name_tmp = NULL;
		nrof_labels++;
	}
	free(name_tmp);
	return nrof_labels;
}
