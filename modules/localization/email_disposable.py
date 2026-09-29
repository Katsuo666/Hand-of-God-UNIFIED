# -*- coding: utf-8 -*-
"""Lista de domínios de email descartável/temporário. Portado do V1 (main.py)."""

DISPOSABLE_EMAIL_DOMAINS = {
    '10mail.org', '10minutemail.com', '10minutemail.net', '123mail.org',
    'tempmail.com', 'tempmail.net', 'tempmail.org', 'temp-mail.org',
    'temp-mail.io', 'throwam.com', 'throwaway.email', 'trashmail.com',
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
    'guerrillamail.info', 'guerrillamail.biz', 'guerrillamail.de',
    'guerrillamailblock.com', 'sharklasers.com', 'yopmail.com', 'yopmail.net',
    'yopmail.fr', 'yopmail.de', 'yopmail.es', 'yopmail.co.uk', 'yopmail.com.br',
    'mailnator.com', 'mailnator.net', 'mailnator.org', 'mailinator.com',
    'mailinator.net', 'mailinator.org', 'mytrashmail.com', 'fakeinbox.com',
    'fakeinbox.net', 'fakeinbox.org', 'mailnull.com', 'spam4me.com', 'spamhole.com',
    'spamgourmet.com', 'spamgourmet.net', 'spamd.de', 'getnada.com', 'getnada.co',
    'maildrop.cc', 'maildrop.net', 'pokemail.net', 'no-spam.ws', 'no-spam.net',
    'nospam.ws', 'emailondeck.com', 'dispostable.com', 'grr.la', 'trashmail.ws',
    'smashmail.de', 'mail-temp.com', 'mailtemp.com.br', 'tempmail.com.br',
    'spam4me.de', 'guerrillamail.fr', 'mailtemp.fr', 'guerrillamail.es',
    'mailtemp.es', 'tempmail.co.uk', 'tempmail.pt', 'guerrillamail.pt',
    'tempmail.it', 'yopmail.it', 'tempmail.nl', 'guerrillamail.nl',
    'tempmail.se', 'guerrillamail.se', 'tempmail.ru', 'guerrillamail.ru',
    'tempmail.jp', 'guerrillamail.jp', 'tempmail.cn', 'guerrillamail.cn',
    'spam4.me', 'spam-me.com', 'spamspot.com',
    'junk1.com', 'junk2.com', 'junkmail.com', 'junkemail.com',
    'fakeemail.com', 'fakemail.net', 'fakeaddress.com', 'truemail.org',
    'truemail.net', 'truemail.com', 'example.com', 'test.com', 'demo.com',
    'nomail.com', 'nosuchmail.com', 'nonexistent.com', 'student.com',
    'studentmail.com', 'testmail.com', 'testmailbox.com', 'schoolmail.com',
    'academicmail.com', '1secmail.com', '20minutemail.com', '2prong.com',
    '3d-painting.com', '3mail.com', '4warding.com', '5mail.info',
    '5-minute-mail.com', '60secondmail.com', '6paq.com', '6url.com',
    '7mail.org', '7mail.net', '7simple.com', '9mail.org',
}


def is_disposable_email(email: str) -> bool:
    """Verifica em O(1) se o email é de um domínio descartável/temporário."""
    if '@' not in email:
        return False
    domain = email.rsplit('@', 1)[1].lower()
    return domain in DISPOSABLE_EMAIL_DOMAINS
