const express = require('express')
const auth = require('../middleware/auth')
const admin = require('../controllers/admin')

const router = express.Router()

router.get('/users', auth.requireUser, auth.requireAdmin, admin.listUsers)
router.post('/users/:id/disable', auth.requireUser, auth.requireAdmin, admin.disableUser)
router.post('/users/:id/role', auth.requireUser, admin.setRole)
router.delete('/users/:id', auth.requireUser, auth.requireAdmin, admin.deleteUser)

module.exports = router
