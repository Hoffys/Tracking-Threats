import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { createClientCredential } from '../middleware/clientAuth.js'

export const clientRoutes = Router()

clientRoutes.post(
  '/public/clients',
  rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  }),
  async (_req, res, next) => {
    try {
      res.status(201).json(await createClientCredential())
    } catch (error) {
      next(error)
    }
  },
)
