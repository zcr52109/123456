const bcrypt = require('bcryptjs');
const express = require('express');
const mongoose = require('mongoose');
const { createAdminUsersHandlers } = require('@fk521ai/api');
const { SystemCapabilities } = require('@fk521ai/data-schemas');
const { SystemRoles } = require('fk521ai-data-provider');
const { requireCapability } = require('~/server/middleware/roles/capabilities');
const { requireJwtAuth } = require('~/server/middleware');
const { getAppConfig } = require('~/server/services/Config');
const db = require('~/models');
const { respondWithStandardError, respondWithInternalError } = require('~/server/utils/respondWithStandardError');

const router = express.Router();

const requireAdminAccess = requireCapability(SystemCapabilities.ACCESS_ADMIN);
const requireReadUsers = requireCapability(SystemCapabilities.READ_USERS);
const requireManageUsers = requireCapability(SystemCapabilities.MANAGE_USERS);

const handlers = createAdminUsersHandlers({
  findUsers: db.findUsers,
  countUsers: db.countUsers,
  deleteUserById: db.deleteUserById,
  deleteConfig: db.deleteConfig,
  deleteAclEntries: db.deleteAclEntries,
});

const USER_FIELDS = '_id name username email avatar role provider emailVerified createdAt updatedAt';

function isAdminUser(user) {
  return String(user?.role || '').trim().toUpperCase() === SystemRoles.ADMIN;
}

function checkAdminAccess(req, res, next) {
  if (isAdminUser(req.user)) {
    return next();
  }
  return requireAdminAccess(req, res, next);
}

function checkReadUsers(req, res, next) {
  if (isAdminUser(req.user)) {
    return next();
  }
  return requireReadUsers(req, res, next);
}

function checkManageUsers(req, res, next) {
  if (isAdminUser(req.user)) {
    return next();
  }
  return requireManageUsers(req, res, next);
}

function normalizeRole(role) {
  const normalized = String(role || '').trim().toUpperCase();
  return normalized === SystemRoles.ADMIN ? SystemRoles.ADMIN : SystemRoles.USER;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeName(name, fallback) {
  const value = String(name || '').trim();
  return value || fallback;
}

function isValidUserId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

async function runAdminHandler(req, res, next, handler, fallbackMessage) {
  try {
    return await Promise.resolve(handler(req, res, next));
  } catch (error) {
    return respondWithInternalError(res, fallbackMessage);
  }
}

router.use(requireJwtAuth, checkAdminAccess);

router.get('/', checkReadUsers, (req, res, next) => runAdminHandler(req, res, next, handlers.listUsers, '读取用户列表失败'));
router.get('/search', checkReadUsers, (req, res, next) => runAdminHandler(req, res, next, handlers.searchUsers, '搜索用户失败'));

router.post('/', checkManageUsers, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');
    const role = normalizeRole(req.body?.role);
    const username = normalizeName(req.body?.username, email.split('@')[0] || `user_${Date.now()}`);
    const name = normalizeName(req.body?.name, username);

    if (!email) {
      return respondWithStandardError(res, 400, { message: '邮箱不能为空', error_code: 'EMAIL_REQUIRED' });
    }
    if (!isValidEmail(email)) {
      return respondWithStandardError(res, 400, { message: '邮箱格式无效', error_code: 'INVALID_EMAIL' });
    }

    if (!password || password.length < 6) {
      return respondWithStandardError(res, 400, { message: '密码至少需要 6 位', error_code: 'INVALID_PASSWORD' });
    }

    const existingUser = await db.findUser({ email }, '_id');
    if (existingUser) {
      return respondWithStandardError(res, 409, { message: '该邮箱已存在，不能重复创建', error_code: 'EMAIL_ALREADY_EXISTS' });
    }

    const appConfig = await getAppConfig({ baseOnly: true });
    const salt = bcrypt.genSaltSync(10);
    const created = await db.createUser(
      {
        provider: 'local',
        email,
        username,
        name,
        role,
        emailVerified: req.body?.emailVerified !== false,
        avatar: null,
        password: bcrypt.hashSync(password, salt),
      },
      appConfig?.balance,
      true,
      true,
    );

    const createdUser = created && typeof created === 'object' ? created : null;
    return res.status(201).json({
      user: {
        id: createdUser?._id?.toString?.() ?? '',
        name: createdUser?.name ?? name,
        username: createdUser?.username ?? username,
        email: createdUser?.email ?? email,
        avatar: createdUser?.avatar ?? '',
        role: createdUser?.role ?? role,
        provider: createdUser?.provider ?? 'local',
        emailVerified: createdUser?.emailVerified ?? true,
        createdAt: createdUser?.createdAt?.toISOString?.(),
        updatedAt: createdUser?.updatedAt?.toISOString?.(),
      },
      message: '用户创建成功',
    });
  } catch (error) {
    return respondWithInternalError(res, '创建用户失败');
  }
});

router.patch('/:id', checkManageUsers, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidUserId(id)) {
      return respondWithStandardError(res, 400, { message: '用户 ID 无效', error_code: 'INVALID_USER_ID' });
    }

    const [targetUser] = await db.findUsers({ _id: id }, USER_FIELDS, { limit: 1 });
    if (!targetUser) {
      return respondWithStandardError(res, 404, { message: '用户不存在', error_code: 'USER_NOT_FOUND' });
    }

    const nextRole = req.body?.role !== undefined ? normalizeRole(req.body.role) : undefined;
    if (String(req.user?.id) === id && nextRole === SystemRoles.USER) {
      return respondWithStandardError(res, 400, {
        message: '不能在当前会话中降级自己的管理员权限',
        error_code: 'SELF_DEMOTE_FORBIDDEN',
      });
    }
    if (targetUser.role === SystemRoles.ADMIN && nextRole === SystemRoles.USER) {
      const adminCount = await db.countUsers({ role: SystemRoles.ADMIN });
      if (adminCount <= 1) {
        return respondWithStandardError(res, 400, { message: '不能降级最后一个管理员账号', error_code: 'LAST_ADMIN_PROTECTED' });
      }
    }

    const nextEmail = req.body?.email !== undefined ? normalizeEmail(req.body.email) : undefined;
    if (nextEmail !== undefined && !nextEmail) {
      return respondWithStandardError(res, 400, { message: '邮箱不能为空', error_code: 'EMAIL_REQUIRED' });
    }
    if (nextEmail && !isValidEmail(nextEmail)) {
      return respondWithStandardError(res, 400, { message: '邮箱格式无效', error_code: 'INVALID_EMAIL' });
    }
    if (nextEmail && nextEmail !== targetUser.email) {
      const existingUser = await db.findUser({ email: nextEmail }, '_id email');
      if (existingUser && String(existingUser._id) !== id) {
        return respondWithStandardError(res, 409, { message: '该邮箱已被其他账号使用', error_code: 'EMAIL_ALREADY_IN_USE' });
      }
    }

    const update = {};
    if (req.body?.name !== undefined) {
      update.name = normalizeName(req.body.name, targetUser.name || targetUser.username || '用户');
    }
    if (req.body?.username !== undefined) {
      update.username = normalizeName(req.body.username, targetUser.username || targetUser.email);
    }
    if (nextEmail !== undefined) {
      update.email = nextEmail;
    }
    if (nextRole !== undefined) {
      update.role = nextRole;
    }
    if (req.body?.emailVerified !== undefined) {
      update.emailVerified = req.body.emailVerified === true;
    }

    const updated = await db.updateUser(id, update);
    if (!updated) {
      return respondWithStandardError(res, 404, { message: '用户不存在', error_code: 'USER_NOT_FOUND' });
    }

    return res.status(200).json({
      user: {
        id: updated._id?.toString?.() ?? '',
        name: updated.name ?? '',
        username: updated.username ?? '',
        email: updated.email ?? '',
        avatar: updated.avatar ?? '',
        role: updated.role ?? SystemRoles.USER,
        provider: updated.provider ?? 'local',
        emailVerified: updated.emailVerified ?? false,
        createdAt: updated.createdAt?.toISOString?.(),
        updatedAt: updated.updatedAt?.toISOString?.(),
      },
      message: '用户信息已更新',
    });
  } catch (error) {
    return respondWithInternalError(res, '更新用户失败');
  }
});

router.post('/:id/reset-password', checkManageUsers, async (req, res) => {
  try {
    const { id } = req.params;
    const password = String(req.body?.password || '');
    if (!isValidUserId(id)) {
      return respondWithStandardError(res, 400, { message: '用户 ID 无效', error_code: 'INVALID_USER_ID' });
    }
    if (!password || password.length < 6) {
      return respondWithStandardError(res, 400, { message: '新密码至少需要 6 位', error_code: 'INVALID_PASSWORD' });
    }

    const [targetUser] = await db.findUsers({ _id: id }, '_id provider', { limit: 1 });
    if (!targetUser) {
      return respondWithStandardError(res, 404, { message: '用户不存在', error_code: 'USER_NOT_FOUND' });
    }

    if (targetUser.provider !== 'local') {
      return respondWithStandardError(res, 400, { message: '仅本地账号支持后台重置密码', error_code: 'PASSWORD_RESET_NOT_SUPPORTED' });
    }

    const salt = bcrypt.genSaltSync(10);
    await db.updateUser(id, {
      password: bcrypt.hashSync(password, salt),
      emailVerified: true,
    });

    return res.status(200).json({ message: '密码已重置' });
  } catch (error) {
    return respondWithInternalError(res, '重置密码失败');
  }
});

router.delete('/:id', checkManageUsers, (req, res, next) => {
  if (String(req.user?.id) === String(req.params?.id)) {
    return respondWithStandardError(res, 400, {
      message: '不允许删除当前登录账号',
      error_code: 'SELF_DELETE_FORBIDDEN',
    });
  }

  return runAdminHandler(req, res, next, handlers.deleteUser, '删除用户失败');
});

module.exports = router;
