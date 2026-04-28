const express = require('express');
const nodemailer = require('nodemailer');
const { respondWithStandardError, respondWithInternalError } = require('~/server/utils/respondWithStandardError');
const { SystemCapabilities } = require('@fk521ai/data-schemas');
const { requireCapability } = require('~/server/middleware/roles/capabilities');
const { requireJwtAuth } = require('~/server/middleware');
const { invalidateConfigCaches } = require('~/server/services/Config');
const {
  readSystemSettings,
  writeSystemSettings,
  hasEmailConfig,
} = require('~/server/utils/adminSystemConfig');

const router = express.Router();
const requireAdminAccess = requireCapability(SystemCapabilities.ACCESS_ADMIN);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.use(requireJwtAuth, requireAdminAccess);

router.get('/', (_req, res) => {
  return res.status(200).json({ settings: readSystemSettings(), emailEnabled: hasEmailConfig() });
});

router.put('/', async (req, res) => {
  try {
    const settings = writeSystemSettings(req.body?.settings || {});
    await invalidateConfigCaches(req.user?.tenantId);
    return res.status(200).json({ settings, emailEnabled: hasEmailConfig(settings) });
  } catch (error) {
    return respondWithInternalError(res, '保存系统设置失败');
  }
});

router.post('/test-email', async (req, res) => {
  try {
    const to = String(req.body?.to || '').trim();
    if (!to) {
      return respondWithStandardError(res, 400, { message: '测试收件邮箱不能为空', error_code: 'TEST_EMAIL_REQUIRED' });
    }
    if (!EMAIL_PATTERN.test(to)) {
      return respondWithStandardError(res, 400, { message: '测试收件邮箱格式不正确', error_code: 'TEST_EMAIL_INVALID' });
    }

    const settings = readSystemSettings();
    if (!hasEmailConfig(settings)) {
      return respondWithStandardError(res, 400, { message: '当前邮箱发送配置不完整，无法发送测试邮件', error_code: 'EMAIL_CONFIG_INCOMPLETE' });
    }

    const { email } = settings;
    const transporterOptions = {
      secure: email.encryption === 'tls',
      requireTls: email.encryption === 'starttls',
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000,
      tls: {
        rejectUnauthorized: !email.allowSelfSigned,
      },
    };

    if (email.encryptionHostname) {
      transporterOptions.tls.servername = email.encryptionHostname;
    }

    if (email.service) {
      transporterOptions.service = email.service;
    } else {
      transporterOptions.host = email.host;
      transporterOptions.port = email.port || 25;
    }

    if (email.username && email.password) {
      transporterOptions.auth = {
        user: email.username,
        pass: email.password,
      };
    }

    const transporter = nodemailer.createTransport(transporterOptions);

    await transporter.sendMail({
      from: `"${email.fromName || 'FK521AI'}" <${email.fromEmail}>`,
      to,
      subject: 'FK521AI 管理后台测试邮件',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111">
          <h2>FK521AI 测试邮件</h2>
          <p>这是一封由管理后台发送的测试邮件。</p>
          <p>发送时间：${new Date().toLocaleString('zh-CN', { hour12: false })}</p>
        </div>
      `,
    });

    return res.status(200).json({ message: `测试邮件已发送到 ${to}` });
  } catch (error) {
    return respondWithInternalError(res, '发送测试邮件失败');
  }
});

module.exports = router;
