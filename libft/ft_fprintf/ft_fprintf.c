#include "ft_fprintf.h"

static int ft_forest_fd (int fd, char c2, va_list va)
{
	int ct;

	ct = 0;
	if (c2 == 'c')
		ct += ft_putchar_fd_ct (fd, (char)va_arg (va, int));
	else if (c2 == 's')
		ct += ft_putstr_fd_ct (fd, (char *)va_arg (va, char *));
	else if (c2 == 'p')
		ct += ft_adress_fd (fd, (unsigned long)va_arg (va, void *));
	else if (c2 == 'd' || c2 == 'i')
		ct += ft_putnbr_fd_ct_1 (fd, (long)va_arg (va, int), "0123456789");
	else if (c2 == 'u')
		ct += ft_putnbr_fd_ct_2 (fd, (unsigned)va_arg (va, int), "0123456789");
	else if (c2 == 'x')
		ct += ft_putnbr_fd_ct_2 (fd, (unsigned)va_arg (va, int),
								 "0123456789abcdef");
	else if (c2 == 'X')
		ct += ft_putnbr_fd_ct_2 (fd, (unsigned)va_arg (va, int),
								 "0123456789ABCDEF");
	else if (c2 == '%')
		ct += ft_putchar_fd_ct (fd, '%');
	return (ct);
}

int ft_check (char c)
{
	if (c == 'c' || c == 's' || c == 'd' || c == 'i')
		return (1);
	if (c == 'u' || c == 'p' || c == 'x' || c == 'X' || c == '%')
		return (1);
	return (0);
}

int ft_parcours_fd (int fd, const char *s, va_list va)
{
	int i;
	int ct;

	i = 0;
	ct = 0;
	while (s[i])
	{
		if (s[i] == '%' && ft_check (s[i + 1]) == 1)
		{
			ct += ft_forest_fd (fd, s[i + 1], va);
			i++;
		}
		else
			ct += ft_putchar_fd_ct (fd, s[i]);
		i++;
	}
	return (ct);
}

int ft_fprintf (int fd, const char *s, ...)
{
	va_list va;
	int		ct;

	ct = 0;
	if (!s)
		return (-1);
	va_start (va, s);
	ct = ft_parcours_fd (fd, s, va);
	va_end (va);
	return (ct);
}