/**
 * 今日の一句 — Code.gs
 * Google Apps Script バックエンド（GitHub Pages + GAS API 構成）
 *
 * ■ 構成
 *  - フロントは GitHub Pages（index.html + app.js）で配信
 *  - このスクリプトはウェブアプリとしてデプロイし、API 専用として利用する
 *  - フロントからは fetch() で POST（Content-Type: text/plain）してアクセスする
 *    → プリフライト(OPTIONS)を発生させないための established パターン
 *
 * ■ セキュリティ設計
 *  - スプレッドシートは非公開（スクリプトのみアクセス）
 *  - 会員登録制：ニックネーム＋メールアドレスで登録し、仮パスワードをメール送信
 *  - パスワードは SHA-256 + ユーザー毎salt + アプリ共通pepper でハッシュ化して保存（平文は一切保存しない）
 *  - pepper は PropertiesService（スクリプトプロパティ）に保存し、初回アクセス時に自動生成
 *  - ログインはメール＋パスワードで行い、成功時に CacheService でセッショントークンを発行（有効期限6時間）
 *  - 投稿の作成はログイン必須。編集・削除は「投稿の memberId」と「セッションの memberId」が一致する場合のみ許可
 *  - ログイン試行 5 回失敗でそのメールアドレスを 15 分ロック
 *  - 全入力値はサーバー側でバリデーション＆サニタイズ
 *  - ContentService.createTextOutput のみ返却（HTML注入不可）
 *  - XSS：フロントは textContent / esc() で描画（HTML挿入なし）
 *  - passwordHash・salt はスプレッドシート上で列非表示にして誤操作による閲覧を防止
 */

/* ============================================================
   設定
   ============================================================ */
const SHEET_NAME       = "posts";     // 投稿シート名
const MEMBERS_SHEET    = "members";   // 会員シート名
const MAX_PHRASE_LEN   = 30;          // 各句フレーズの最大文字数
const MAX_COMMENT_LEN  = 60;          // コメントの最大文字数
const MAX_NICKNAME_LEN = 20;          // ニックネームの最大文字数
const MAX_POSTS_PER_FETCH = 100;      // 一度に取得する最大件数
const VALID_GENERATIONS = ["teen", "twenties", "forties", "senior"];
const VALID_TYPES       = ["haiku", "tanka"];

const SESSION_TTL_SEC     = 21600;    // セッション有効期限＝6時間（CacheServiceの最大値）
const MAX_LOGIN_ATTEMPTS  = 5;        // ログイン失敗許容回数
const LOCK_DURATION_MS    = 15 * 60 * 1000; // ロック時間＝15分
const TEMP_PASSWORD_LEN   = 10;

const APP_NAME = "今日の一句";

/* 投稿シートの列定義（1-indexed） */
const COL = {
  ID:         1,
  TYPE:       2,
  PHRASES:    3,   // JSON文字列
  COMMENT:    4,
  GENERATION: 5,
  MEMBER_ID:  6,   // 投稿者の会員ID（閲覧者には返さない）
  NICKNAME:   7,   // 投稿時点のニックネーム（表示用スナップショット）
  TIMESTAMP:  8,
  ZAB_TEEN:   9,
  ZAB_TWENTY: 10,
  ZAB_FORTY:  11,
  ZAB_SENIOR: 12,
};
const TOTAL_COLS = 12;

/* 会員シートの列定義（1-indexed） */
const MCOL = {
  ID:            1,
  NICKNAME:      2,
  EMAIL:         3,
  PASSWORD_HASH: 4,
  SALT:          5,
  MUST_CHANGE:   6,
  FAILED_COUNT:  7,
  LOCKED_UNTIL:  8,
  CREATED_AT:    9,
};
const MEMBER_TOTAL_COLS = 9;

/* ============================================================
   エントリポイント
   ============================================================ */

/**
 * GETリクエスト（簡易ヘルスチェック用）
 * フロントは基本的に doPost を使う。?p=payload 形式の GET も後方互換のため残す。
 */
function doGet(e) {
  const p = e && e.parameter && (e.parameter.p || e.parameter.payload);
  if (p) {
    return runDispatchAndRespond(() => {
      let decoded;
      try {
        decoded = Utilities.newBlob(Utilities.base64Decode(p)).getDataAsString();
        JSON.parse(decoded);
      } catch (_) {
        decoded = decodeURIComponent(p);
      }
      return JSON.parse(decoded);
    });
  }
  return ContentService
    .createTextOutput(JSON.stringify({ ok: true, data: { message: APP_NAME + " API is running" } }))
    .setMimeType(ContentService.MimeType.JSON);
}

/** POSTリクエスト → API（メインの通信経路） */
function doPost(e) {
  return runDispatchAndRespond(() => {
    if (!e || !e.postData || !e.postData.contents) throw new AppError("リクエストが不正です");
    return JSON.parse(e.postData.contents);
  });
}

function runDispatchAndRespond(getPayloadFn) {
  const output = ContentService.createTextOutput();
  output.setMimeType(ContentService.MimeType.JSON);
  try {
    const payload = getPayloadFn();
    const result  = dispatch(payload);
    output.setContent(JSON.stringify({ ok: true, data: result }));
  } catch (err) {
    Logger.log("API error: " + (err && err.stack ? err.stack : err));
    const msg = err instanceof AppError ? err.message : "サーバーエラーが発生しました";
    output.setContent(JSON.stringify({ ok: false, error: msg }));
  }
  return output;
}

/* ============================================================
   ルーティング
   ============================================================ */
function dispatch(payload) {
  const action = String(payload.action || "");
  switch (action) {
    // 会員系
    case "register":         return actionRegister(payload);
    case "login":             return actionLogin(payload);
    case "logout":            return actionLogout(payload);
    case "changePassword":    return actionChangePassword(payload);
    case "forgotPassword":    return actionForgotPassword(payload);
    case "checkSession":      return actionCheckSession(payload);
    // 投稿系
    case "getPosts":    return actionGetPosts(payload);
    case "createPost":  return actionCreatePost(payload);
    case "editPost":    return actionEditPost(payload);
    case "deletePost":  return actionDeletePost(payload);
    case "zabuton":     return actionZabuton(payload);
    default: throw new AppError("不明なアクションです");
  }
}

/* ============================================================
   会員アクション
   ============================================================ */

/** 新規会員登録：ニックネーム＋メールアドレス → 仮パスワード発行・メール送信 */
function actionRegister(payload) {
  const nickname = sanitizeText(payload.nickname || "", MAX_NICKNAME_LEN);
  const email    = normalizeEmail(payload.email || "");

  if (!nickname) throw new AppError("ニックネームを入力してください");
  if (!isValidEmail(email)) throw new AppError("メールアドレスの形式が正しくありません");

  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const sheet = getMembersSheet();
    if (findMemberRowByEmail(sheet, email)) {
      throw new AppError("このメールアドレスはすでに登録されています");
    }

    const tempPassword = generateTempPassword();
    const salt = Utilities.getUuid();
    const hash = hashPassword(tempPassword, salt);
    const id   = Utilities.getUuid();
    const now  = new Date().getTime();

    sheet.appendRow([
      id, nickname, email, hash, salt,
      true,   // mustChangePassword
      0,      // failedCount
      0,      // lockedUntil
      now,
    ]);

    sendMail(
      email,
      `【${APP_NAME}】仮パスワードのお知らせ`,
      `${nickname} 様\n\n${APP_NAME}にご登録いただきありがとうございます。\n` +
      `以下の仮パスワードでログインし、初回ログイン時に新しいパスワードを設定してください。\n\n` +
      `仮パスワード：${tempPassword}\n\n` +
      `※このメールに心当たりがない場合は破棄してください。`
    );

    return { ok: true, email };
  } finally {
    lock.releaseLock();
  }
}

/** ログイン */
function actionLogin(payload) {
  const email    = normalizeEmail(payload.email || "");
  const password = String(payload.password || "");
  if (!email || !password) throw new AppError("メールアドレスとパスワードを入力してください");

  const sheet = getMembersSheet();
  const rowIndex = findMemberRowByEmail(sheet, email);
  if (!rowIndex) throw new AppError("メールアドレスまたはパスワードが正しくありません");

  const row = sheet.getRange(rowIndex, 1, 1, MEMBER_TOTAL_COLS).getValues()[0];
  const lockedUntil = Number(row[MCOL.LOCKED_UNTIL - 1] || 0);
  const now = new Date().getTime();

  if (lockedUntil && now < lockedUntil) {
    const remainMin = Math.ceil((lockedUntil - now) / 60000);
    throw new AppError(`ログイン試行回数が上限に達しました。${remainMin}分後に再度お試しください`);
  }

  const salt = String(row[MCOL.SALT - 1]);
  const storedHash = String(row[MCOL.PASSWORD_HASH - 1]);
  const inputHash  = hashPassword(password, salt);

  if (inputHash !== storedHash) {
    const failedCount = Number(row[MCOL.FAILED_COUNT - 1] || 0) + 1;
    sheet.getRange(rowIndex, MCOL.FAILED_COUNT).setValue(failedCount);
    if (failedCount >= MAX_LOGIN_ATTEMPTS) {
      sheet.getRange(rowIndex, MCOL.LOCKED_UNTIL).setValue(now + LOCK_DURATION_MS);
      throw new AppError("ログイン試行回数が上限に達したため、15分間ロックされました");
    }
    throw new AppError("メールアドレスまたはパスワードが正しくありません");
  }

  // 成功：失敗カウントとロックをリセット
  sheet.getRange(rowIndex, MCOL.FAILED_COUNT).setValue(0);
  sheet.getRange(rowIndex, MCOL.LOCKED_UNTIL).setValue(0);

  const memberId = String(row[MCOL.ID - 1]);
  const nickname = String(row[MCOL.NICKNAME - 1]);
  const mustChangePassword = Boolean(row[MCOL.MUST_CHANGE - 1]);

  const token = createSession(memberId, nickname);

  return { token, nickname, mustChangePassword };
}

/** ログアウト */
function actionLogout(payload) {
  const token = String(payload.token || "");
  if (token) CacheService.getScriptCache().remove(sessionCacheKey(token));
  return { ok: true };
}

/** セッション有効確認（画面再読込時などに使用） */
function actionCheckSession(payload) {
  const session = getSession(payload.token);
  if (!session) throw new AppError("セッションが切れました。再度ログインしてください");
  return { nickname: session.nickname };
}

/** パスワード変更（初回強制変更・任意変更の両方に対応） */
function actionChangePassword(payload) {
  const session = requireSession(payload.token);
  const newPassword = String(payload.newPassword || "");
  if (newPassword.length < 8) throw new AppError("新しいパスワードは8文字以上にしてください");

  const sheet = getMembersSheet();
  const rowIndex = findMemberRowById(sheet, session.memberId);
  if (!rowIndex) throw new AppError("会員情報が見つかりません");

  const row = sheet.getRange(rowIndex, 1, 1, MEMBER_TOTAL_COLS).getValues()[0];
  const mustChange = Boolean(row[MCOL.MUST_CHANGE - 1]);

  // 強制変更フローでなければ現在のパスワード確認が必要
  if (!mustChange) {
    const oldPassword = String(payload.oldPassword || "");
    const salt = String(row[MCOL.SALT - 1]);
    const storedHash = String(row[MCOL.PASSWORD_HASH - 1]);
    if (hashPassword(oldPassword, salt) !== storedHash) {
      throw new AppError("現在のパスワードが正しくありません");
    }
  }

  const newSalt = Utilities.getUuid();
  const newHash = hashPassword(newPassword, newSalt);
  sheet.getRange(rowIndex, MCOL.PASSWORD_HASH).setValue(newHash);
  sheet.getRange(rowIndex, MCOL.SALT).setValue(newSalt);
  sheet.getRange(rowIndex, MCOL.MUST_CHANGE).setValue(false);

  return { ok: true };
}

/** パスワード忘れ：仮パスワードを再発行してメール送信 */
function actionForgotPassword(payload) {
  const email = normalizeEmail(payload.email || "");
  if (!isValidEmail(email)) throw new AppError("メールアドレスの形式が正しくありません");

  const sheet = getMembersSheet();
  const rowIndex = findMemberRowByEmail(sheet, email);
  // メールアドレスの存在有無を外部に漏らさないため、見つからない場合も成功と同じ応答にする
  if (!rowIndex) return { ok: true };

  const nickname = String(sheet.getRange(rowIndex, MCOL.NICKNAME).getValue());
  const tempPassword = generateTempPassword();
  const newSalt = Utilities.getUuid();
  const newHash = hashPassword(tempPassword, newSalt);

  sheet.getRange(rowIndex, MCOL.PASSWORD_HASH).setValue(newHash);
  sheet.getRange(rowIndex, MCOL.SALT).setValue(newSalt);
  sheet.getRange(rowIndex, MCOL.MUST_CHANGE).setValue(true);
  sheet.getRange(rowIndex, MCOL.FAILED_COUNT).setValue(0);
  sheet.getRange(rowIndex, MCOL.LOCKED_UNTIL).setValue(0);

  sendMail(
    email,
    `【${APP_NAME}】仮パスワード再発行のお知らせ`,
    `${nickname} 様\n\n仮パスワードを再発行しました。\n` +
    `以下の仮パスワードでログインし、初回ログイン時に新しいパスワードを設定してください。\n\n` +
    `仮パスワード：${tempPassword}\n\n` +
    `※このお手続きに心当たりがない場合は、このメールを破棄しパスワードはそのままにしてください。`
  );

  return { ok: true };
}

/* ============================================================
   投稿アクション
   ============================================================ */

/** 投稿一覧取得（誰でも閲覧可。tokenがあれば isOwner を付与） */
function actionGetPosts(payload) {
  const sheet = getSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return { posts: [] };

  const session = payload.token ? getSession(payload.token) : null;
  const currentMemberId = session ? session.memberId : null;

  const numRows = Math.min(lastRow - 1, MAX_POSTS_PER_FETCH);
  const data    = sheet.getRange(2, 1, numRows, TOTAL_COLS).getValues();

  const posts = data
    .filter(row => row[COL.ID - 1])  // 空行スキップ
    .map(row => rowToPublicPost(row, currentMemberId));

  return { posts };
}

/** 新規投稿（ログイン必須） */
function actionCreatePost(payload) {
  const session = requireSession(payload.token);
  const { type, phrases, comment, generation } = payload;

  validateType(type);
  validatePhrases(type, phrases);
  validateGeneration(generation);
  const cleanComment = sanitizeText(comment || "", MAX_COMMENT_LEN);

  const sheet = getSheet();
  const id    = Utilities.getUuid();
  const now   = new Date().getTime();

  sheet.appendRow([
    id,
    type,
    JSON.stringify(phrases.map(p => sanitizeText(p, MAX_PHRASE_LEN))),
    cleanComment,
    generation,
    session.memberId,
    session.nickname,
    now,
    0, 0, 0, 0,       // zabuton（世代別）
  ]);

  return { id, timestamp: now, nickname: session.nickname };
}

/** 投稿編集（本人のみ） */
function actionEditPost(payload) {
  const session = requireSession(payload.token);
  const { postId, type, phrases, comment, generation } = payload;

  validateType(type);
  validatePhrases(type, phrases);
  validateGeneration(generation);
  const cleanComment = sanitizeText(comment || "", MAX_COMMENT_LEN);

  const { sheet, rowIndex } = requirePostOwner(postId, session.memberId);

  sheet.getRange(rowIndex, COL.TYPE).setValue(type);
  sheet.getRange(rowIndex, COL.PHRASES).setValue(
    JSON.stringify(phrases.map(p => sanitizeText(p, MAX_PHRASE_LEN)))
  );
  sheet.getRange(rowIndex, COL.COMMENT).setValue(cleanComment);
  sheet.getRange(rowIndex, COL.GENERATION).setValue(generation);

  return { ok: true };
}

/** 投稿削除（本人のみ） */
function actionDeletePost(payload) {
  const session = requireSession(payload.token);
  const { postId } = payload;

  const { sheet, rowIndex } = requirePostOwner(postId, session.memberId);
  sheet.deleteRow(rowIndex);

  return { ok: true };
}

/** 座布団（いいね）：閲覧は誰でも可なので座布団も未ログインで可（重複防止はクライアント側localStorage） */
function actionZabuton(payload) {
  const { postId, generation } = payload;
  validateGeneration(generation);

  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const sheet    = getSheet();
    const rowIndex = findRowById(sheet, postId);
    if (!rowIndex) throw new AppError("投稿が見つかりません");

    const colMap = {
      teen:     COL.ZAB_TEEN,
      twenties: COL.ZAB_TWENTY,
      forties:  COL.ZAB_FORTY,
      senior:   COL.ZAB_SENIOR,
    };
    const col  = colMap[generation];
    const cell = sheet.getRange(rowIndex, col);
    cell.setValue(Number(cell.getValue()) + 1);

    const row = sheet.getRange(rowIndex, 1, 1, TOTAL_COLS).getValues()[0];
    return {
      zabuton: {
        teen:     Number(row[COL.ZAB_TEEN - 1]),
        twenties: Number(row[COL.ZAB_TWENTY - 1]),
        forties:  Number(row[COL.ZAB_FORTY - 1]),
        senior:   Number(row[COL.ZAB_SENIOR - 1]),
      }
    };
  } finally {
    lock.releaseLock();
  }
}

/* ============================================================
   シート系ヘルパー
   ============================================================ */

function getSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow([
      "id","type","phrases","comment","generation",
      "member_id","nickname","timestamp",
      "zab_teen","zab_twenties","zab_forties","zab_senior"
    ]);
    sheet.setFrozenRows(1);
    // member_id 列を非表示（外部ツールから見えにくくする）
    sheet.hideColumns(COL.MEMBER_ID);
  }
  return sheet;
}

function getMembersSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(MEMBERS_SHEET);
  if (!sheet) {
    sheet = ss.insertSheet(MEMBERS_SHEET);
    sheet.appendRow([
      "id","nickname","email","passwordHash","salt",
      "mustChangePassword","failedCount","lockedUntil","createdAt"
    ]);
    sheet.setFrozenRows(1);
    // パスワード関連の列は非表示にして誤操作による閲覧・コピーを防止
    sheet.hideColumns(MCOL.PASSWORD_HASH, 2); // passwordHash, salt
  }
  return sheet;
}

/** 行データ → クライアントに返すオブジェクト（member_id を除外、isOwnerのみ付与） */
function rowToPublicPost(row, currentMemberId) {
  let phrases = [];
  try { phrases = JSON.parse(row[COL.PHRASES - 1]); } catch (_) {}

  const storedMemberId = String(row[COL.MEMBER_ID - 1] || "");

  return {
    id:         String(row[COL.ID - 1]),
    type:       String(row[COL.TYPE - 1]),
    phrases:    phrases,
    comment:    String(row[COL.COMMENT - 1] || ""),
    generation: String(row[COL.GENERATION - 1]),
    nickname:   String(row[COL.NICKNAME - 1] || ""),
    timestamp:  Number(row[COL.TIMESTAMP - 1]),
    isOwner:    Boolean(currentMemberId) && storedMemberId === currentMemberId,
    zabuton: {
      teen:     Number(row[COL.ZAB_TEEN - 1]   || 0),
      twenties: Number(row[COL.ZAB_TWENTY - 1] || 0),
      forties:  Number(row[COL.ZAB_FORTY - 1]  || 0),
      senior:   Number(row[COL.ZAB_SENIOR - 1] || 0),
    },
    // member_id は絶対に返さない
  };
}

function findRowById(sheet, postId) {
  if (!postId) return null;
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return null;
  const ids = sheet.getRange(2, COL.ID, lastRow - 1, 1).getValues();
  for (let i = 0; i < ids.length; i++) {
    if (String(ids[i][0]) === String(postId)) return i + 2;
  }
  return null;
}

function requirePostOwner(postId, memberId) {
  const sheet    = getSheet();
  const rowIndex = findRowById(sheet, postId);
  if (!rowIndex) throw new AppError("投稿が見つかりません");

  const storedMemberId = String(sheet.getRange(rowIndex, COL.MEMBER_ID).getValue());
  if (storedMemberId !== memberId) {
    throw new AppError("編集・削除の権限がありません");
  }
  return { sheet, rowIndex };
}

function findMemberRowByEmail(sheet, email) {
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return null;
  const emails = sheet.getRange(2, MCOL.EMAIL, lastRow - 1, 1).getValues();
  for (let i = 0; i < emails.length; i++) {
    if (String(emails[i][0]).toLowerCase() === email) return i + 2;
  }
  return null;
}

function findMemberRowById(sheet, memberId) {
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return null;
  const ids = sheet.getRange(2, MCOL.ID, lastRow - 1, 1).getValues();
  for (let i = 0; i < ids.length; i++) {
    if (String(ids[i][0]) === String(memberId)) return i + 2;
  }
  return null;
}

/* ============================================================
   セッション（CacheService）
   ============================================================ */

function sessionCacheKey(token) {
  return "session_" + token;
}

function createSession(memberId, nickname) {
  const token = Utilities.getUuid();
  CacheService.getScriptCache().put(
    sessionCacheKey(token),
    JSON.stringify({ memberId, nickname }),
    SESSION_TTL_SEC
  );
  return token;
}

function getSession(token) {
  if (!token || typeof token !== "string") return null;
  const raw = CacheService.getScriptCache().get(sessionCacheKey(token));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function requireSession(token) {
  const session = getSession(token);
  if (!session) throw new AppError("ログインが必要です。再度ログインしてください");
  return session;
}

/* ============================================================
   パスワード関連ユーティリティ
   ============================================================ */

/** アプリ共通pepper。スクリプトプロパティに保存し、初回アクセス時に自動生成する */
function getPepper() {
  const props = PropertiesService.getScriptProperties();
  let pepper = props.getProperty("PEPPER");
  if (!pepper) {
    pepper = Utilities.getUuid() + Utilities.getUuid();
    props.setProperty("PEPPER", pepper);
  }
  return pepper;
}

function hashPassword(password, salt) {
  const input = String(password) + String(salt) + getPepper();
  const rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input, Utilities.Charset.UTF_8);
  return rawHash.map(b => ((b < 0 ? b + 256 : b).toString(16)).padStart(2, "0")).join("");
}

function generateTempPassword() {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"; // 紛らわしい文字(0,O,1,l,I)を除外
  let result = "";
  for (let i = 0; i < TEMP_PASSWORD_LEN; i++) {
    result += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return result;
}

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sendMail(to, subject, body) {
  try {
    MailApp.sendEmail(to, subject, body);
  } catch (err) {
    Logger.log("メール送信エラー: " + err.message);
    throw new AppError("メール送信に失敗しました。時間をおいて再度お試しください");
  }
}

/* ============================================================
   バリデーション＆サニタイズ
   ============================================================ */

class AppError extends Error {
  constructor(msg) { super(msg); this.name = "AppError"; }
}

function validateType(type) {
  if (!VALID_TYPES.includes(type)) throw new AppError("不正な句種別です");
}

function validateGeneration(gen) {
  if (!VALID_GENERATIONS.includes(gen)) throw new AppError("不正な世代値です");
}

function validatePhrases(type, phrases) {
  if (!Array.isArray(phrases)) throw new AppError("句の形式が不正です");
  const expected = type === "haiku" ? 3 : 5;
  if (phrases.length !== expected) throw new AppError("句のフレーズ数が正しくありません");
  for (const p of phrases) {
    if (typeof p !== "string" || !p.trim()) throw new AppError("空の句フレーズがあります");
    if (p.length > MAX_PHRASE_LEN) throw new AppError(`句フレーズは${MAX_PHRASE_LEN}文字以内にしてください`);
  }
}

/** 文字列のサニタイズ（制御文字除去・長さ制限） */
function sanitizeText(str, maxLen) {
  if (typeof str !== "string") return "";
  return str.replace(/[^\S\n\t]/g, " ").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").slice(0, maxLen).trim();
}
