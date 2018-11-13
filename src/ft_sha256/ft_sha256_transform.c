/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha256_transform.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 18:37:30 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 18:37:32 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_sha256_constants.h"
#include "ft_sha256.h"

void							sha256_setvars(\
	t_sha256_tvars *vars,\
	t_sha256_ctx *ctx)
{
	vars->a = ctx->state[0];
	vars->b = ctx->state[1];
	vars->c = ctx->state[2];
	vars->d = ctx->state[3];
	vars->e = ctx->state[4];
	vars->f = ctx->state[5];
	vars->g = ctx->state[6];
	vars->h = ctx->state[7];
	vars->i = 0;
}

void							sha256_rounds(t_sha256_tvars *vars)
{
	vars->t1 = vars->h + EP1(vars->e) + CH(vars->e, vars->f, vars->g)\
		+ g_k_values[vars->i] + vars->m[vars->i];
	vars->t2 = EP0(vars->a) + MAJ(vars->a, vars->b, vars->c);
	vars->h = vars->g;
	vars->g = vars->f;
	vars->f = vars->e;
	vars->e = vars->d + vars->t1;
	vars->d = vars->c;
	vars->c = vars->b;
	vars->b = vars->a;
	vars->a = vars->t1 + vars->t2;
	++vars->i;
}

void							sha256_setstate(\
	t_sha256_tvars *vars,\
	t_sha256_ctx *ctx)
{
	ctx->state[0] += vars->a;
	ctx->state[1] += vars->b;
	ctx->state[2] += vars->c;
	ctx->state[3] += vars->d;
	ctx->state[4] += vars->e;
	ctx->state[5] += vars->f;
	ctx->state[6] += vars->g;
	ctx->state[7] += vars->h;
}

void							sha256_transform(\
	t_sha256_ctx *ctx,\
	const uint8_t data[])
{
	t_sha256_tvars		vars;

	vars.i = 0;
	vars.j = 0;
	while (vars.i < 16)
	{
		vars.m[vars.i] = (data[vars.j] << 24) | (data[vars.j + 1] << 16)\
		| (data[vars.j + 2] << 8) | (data[vars.j + 3]);
		++vars.i;
		vars.j += 4;
	}
	while (vars.i < 64)
	{
		vars.m[vars.i] = SIG1(vars.m[vars.i - 2]) + vars.m[vars.i - 7] +\
		SIG0(vars.m[vars.i - 15]) + vars.m[vars.i - 16];
		++vars.i;
	}
	sha256_setvars(&vars, ctx);
	while (vars.i < 64)
		sha256_rounds(&vars);
	sha256_setstate(&vars, ctx);
}
