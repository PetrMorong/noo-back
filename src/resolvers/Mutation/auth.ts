import * as bcrypt from 'bcryptjs'
import * as jwt from 'jsonwebtoken'
import { Context, createToken, getUserId } from '../../utils';

export const auth = {
  async refreshToken(parent, { token }, ctx: Context, info) {
    const userId = getUserId(ctx, token);
    const user = await ctx.db.query.user({ where: { id: userId } })

    return {
      token: createToken(userId),
      user,
    }
  },

  async signup(parent, args, ctx: Context, info) {
    const password = await bcrypt.hash(args.password, 10)
    const user = await ctx.db.mutation.createUser({
      data: { ...args, password },
    })

    return {
      token: createToken(user.id),
      user,
    }
  },

  async login(parent, { email, password }, ctx: Context, info) {
    const user = await ctx.db.query.user({ where: { email } })
    if (!user) {
      return {
        error: {
          field: 'email',
          msg: 'No user found'
        }
      }
    }

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      return {
        error: {
          field: 'password',
          msg: 'Wrong password'
        }
      }
    }

    console.log(user)

    return {
      payload: {
        token: jwt.sign({ userId: user.id }, process.env.APP_SECRET),
        user,
      }
    }
  },
}
