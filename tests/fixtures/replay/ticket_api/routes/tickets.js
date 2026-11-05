const express = require('express')
const auth = require('../middleware/auth')
const tickets = require('../controllers/tickets')

const router = express.Router()

router.get('/tickets', auth.requireUser, tickets.list)
router.post('/tickets', auth.requireUser, tickets.create)
router.get('/tickets/:id', auth.requireUser, tickets.show)
router.put('/tickets/:id', auth.requireUser, tickets.update)
router.delete('/tickets/:id', auth.requireUser, tickets.remove)
router.get('/tickets/:id/history', tickets.history)
router.get('/tickets/:id/comments', auth.requireUser, tickets.listComments)
router.post('/tickets/:id/comments', auth.requireUser, tickets.addComment)
router.get('/comments/:commentId', auth.requireUser, tickets.showComment)

module.exports = router
