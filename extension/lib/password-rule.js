// New-password rule of NCALayer for PKCS#12 files (KeyStoreUtil.validatePasswordPattern,
// knca_provider_util 0.8.8). Shared by the password page and the crypto worker.
export const CHANGE_PASSWORD_RULE = /^(?=.*\d)(?=.*[a-zA-Z])[0-9a-zA-Z.?#$^+=!*()@%&_-]{6,32}$/;
export const CHANGE_PASSWORD_HINT = 'Новый пароль: 6–32 символа, латинские буквы и цифры, допустимы . ? # $ ^ + = ! * ( ) @ % & _ -';

export function passwordChecks(value, current = '', repeat = value) {
  return {
    length: value.length >= 6 && value.length <= 32,
    mix: /[a-zA-Z]/.test(value) && /\d/.test(value),
    chars: /^[0-9a-zA-Z.?#$^+=!*()@%&_-]*$/.test(value),
    differs: value !== current,
    repeat: value === repeat
  };
}
