/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr_ct_2.c                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vkerob <vkerob@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/10/20 13:31:21 by neweth            #+#    #+#             */
/*   Updated: 2022/11/04 17:19:27 by vkerob           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_fprintf.h"

int ft_putnbr_fd_ct_2 (int fd, unsigned int nbr, char *base)
{
	unsigned int len_base;
	int			 ct;

	ct = 0;
	len_base = ft_strlen (base);
	if (nbr < len_base)
		ct += ft_putchar_fd_ct (fd, base[nbr]);
	else
	{
		ct += ft_putnbr_fd_ct_2 (fd, nbr / len_base, base);
		ct += ft_putchar_fd_ct (fd, base[nbr % len_base]);
	}
	return (ct);
}
