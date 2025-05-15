#include "ft_fprintf.h"

int ft_putnbr_fd_ct_1 (int fd, long nbr, char *base)
{
	int len_base;
	int ct;

	ct = 0;
	len_base = ft_strlen (base);
	if (nbr < 0)
	{
		ct += ft_putchar_fd_ct (fd, '-');
		nbr = -nbr;
	}
	if (nbr < len_base)
		ct += ft_putchar_fd_ct (fd, base[nbr % len_base]);
	else
	{
		ct += ft_putnbr_fd_ct_1 (fd, nbr / len_base, base);
		ct += ft_putchar_fd_ct (fd, base[nbr % len_base]);
	}
	return (ct);
}
