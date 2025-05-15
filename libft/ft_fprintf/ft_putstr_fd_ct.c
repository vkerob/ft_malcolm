/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putstr_ct.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkerob <vkerob@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/10/18 17:45:40 by vkerob            #+#    #+#             */
/*   Updated: 2022/11/14 11:53:57 by vkerob           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_fprintf.h"

int ft_putstr_fd_ct (int fd, char *s)
{
	int i;
	int ct;

	ct = 0;
	i = 0;
	if (!s)
	{
		write (fd, "(null)", 6);
		return (6);
	}
	while (s[i])
	{
		write (fd, &s[i], 1);
		i++;
		ct++;
	}
	return (ct);
}
