#ifndef FT_FPRINTF_H
#define FT_FPRINTF_H

#include <stdarg.h>
#include <unistd.h>

int	   ft_fprintf (int fd, const char *s, ...);
size_t ft_strlen (const char *str);
int	   ft_putchar_fd_ct (int fd, char c);
int	   ft_putnbr_fd_ct_1 (int fd, long nbr, char *base);
int	   ft_putstr_fd_ct (int fd, char *s);
int	   ft_putnbr_fd_ct_2 (int fd, unsigned int nbr, char *base);
int	   ft_adress_fd (int fd, unsigned long nbr);

#endif
