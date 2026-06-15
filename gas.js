/**
 * 今日の一句 — Code.gs
 * Google Apps Script バックエンド
 *
 * ■ セキュリティ設計
 *  - スプレッドシートは非公開（スクリプトのみアクセス）
 *  - 投稿者はサーバー側で発行した SESSION_ID（UUID）で識別
 *  - 編集・削除は SESSION_ID が一致する行のみ許可
 *  - 全入力値はサーバー側でバリデーション＆サニタイズ
 *  - doPost は JSON-RPC スタイルで action を明示
 *  - ContentService.createTextOutput のみ返却（HTML注入不可）
 *  - XSS：フロントは textContent で描画（HTML挿入なし）
 */

/* ============================================================
   設定
   ============================================================ */
const SHEET_NAME    = "posts";       // スプレッドシートのシート名
const MAX_PHRASE_LEN = 30;           // 各句フレーズの最大文字数
const MAX_COMMENT_LEN = 60;          // コメントの最大文字数
const MAX_POSTS_PER_FETCH = 100;     // 一度に取得する最大件数
const VALID_GENERATIONS = ["teen", "twenties", "forties", "senior"];
const VALID_TYPES       = ["haiku", "tanka"];

/* スプレッドシートの列定義（1-indexed） */
const COL = {
  ID:         1,
  TYPE:       2,
  PHRASES:    3,   // JSON文字列
  COMMENT:    4,
  GENERATION: 5,
  SESSION_ID: 6,   // 閲覧者には返さない
  TIMESTAMP:  7,
  ZAB_TEEN:   8,
  ZAB_TWENTY: 9,
  ZAB_FORTY:  10,
  ZAB_SENIOR: 11,
};
const TOTAL_COLS = 11;

/* ============================================================
   エントリポイント
   ============================================================ */

/**
 * GETリクエスト
 *  - ?p=... がある → API呼び出し（JSON返却）
 *  - パラメータなし → Webアプリ画面を返す
 *
 * ペイロードは Base64 エンコードで送受信する。
 * （URLエンコードの二重処理を避けるため）
 */
function doGet(e) {
  // どんなパラメータが来ているかをまずログ出力
  Logger.log("doGet called. parameters: " + JSON.stringify(e ? e.parameter : null));

  // API呼び出し：パラメータ p または payload があればAPI処理
  const p = e && e.parameter && (e.parameter.p || e.parameter.payload);
  if (p) {
    const output = ContentService.createTextOutput();
    output.setMimeType(ContentService.MimeType.JSON);
    try {
      let decoded;
      // Base64デコードを試みる、失敗したらURLデコードとして扱う
      try {
        decoded = Utilities.newBlob(Utilities.base64Decode(p)).getDataAsString();
        // Base64デコード結果がJSONでなければURLデコードを試みる
        JSON.parse(decoded);
      } catch(_) {
        decoded = decodeURIComponent(p);
      }
      const payload = JSON.parse(decoded);
      const result  = dispatch(payload);
      output.setContent(JSON.stringify({ ok: true, data: result }));
    } catch (err) {
      Logger.log("API error: " + err.message);
      const msg = err instanceof AppError ? err.message : "サーバーエラーが発生しました";
      output.setContent(JSON.stringify({ ok: false, error: msg }));
    }
    return output;
  }

  // 通常アクセス → HTMLページを返す
  return HtmlService
    .createTemplateFromFile("index")
    .evaluate()
    .setTitle("今日の一句")
    .addMetaTag("viewport", "width=device-width, initial-scale=1.0");
}

/**
 * google.script.run から呼び出されるサーバー関数
 * HtmlService で配信されたページ内から直接呼び出す最も確実な方法。
 */
function handleRequest(payloadJson) {
  try {
    const payload = JSON.parse(payloadJson);
    const result  = dispatch(payload);
    return { ok: true, data: result };
  } catch (err) {
    const msg = err instanceof AppError ? err.message : "サーバーエラーが発生しました";
    return { ok: false, error: msg };
  }
}

/** POSTリクエスト → API（フォールバック用） */
function doPost(e) {
  const output = ContentService.createTextOutput();
  output.setMimeType(ContentService.MimeType.JSON);
  try {
    const payload = JSON.parse(e.postData.contents);
    const result  = dispatch(payload);
    output.setContent(JSON.stringify({ ok: true, data: result }));
  } catch (err) {
    const msg = err instanceof AppError ? err.message : "サーバーエラーが発生しました";
    output.setContent(JSON.stringify({ ok: false, error: msg }));
  }
  return output;
}


/** HTMLファイルのインクルード（Templateヘルパー） */
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

/* ============================================================
   ルーティング
   ============================================================ */
function dispatch(payload) {
  const action = String(payload.action || "");
  switch (action) {
    case "getPosts":    return actionGetPosts(payload);
    case "createPost":  return actionCreatePost(payload);
    case "editPost":    return actionEditPost(payload);
    case "deletePost":  return actionDeletePost(payload);
    case "zabuton":     return actionZabuton(payload);
    default: throw new AppError("不明なアクションです");
  }
}

/* ============================================================
   アクション実装
   ============================================================ */

/** 投稿一覧取得 */
function actionGetPosts(payload) {
  const sheet = getSheet();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return { posts: [] };

  const numRows = Math.min(lastRow - 1, MAX_POSTS_PER_FETCH);
  const data    = sheet.getRange(2, 1, numRows, TOTAL_COLS).getValues();

  const posts = data
    .filter(row => row[COL.ID - 1])  // 空行スキップ
    .map(row => rowToPublicPost(row));

  return { posts };
}

/** 新規投稿 */
function actionCreatePost(payload) {
  const { type, phrases, comment, generation, sessionId } = payload;

  validateType(type);
  validatePhrases(type, phrases);
  validateGeneration(generation);
  const cleanComment  = sanitizeText(comment || "", MAX_COMMENT_LEN);
  const cleanSessionId = validateSessionId(sessionId);

  const sheet = getSheet();
  const id    = Utilities.getUuid();
  const now   = new Date().getTime();

  sheet.appendRow([
    id,
    type,
    JSON.stringify(phrases.map(p => sanitizeText(p, MAX_PHRASE_LEN))),
    cleanComment,
    generation,
    cleanSessionId,   // ← 外部には公開しない
    now,
    0, 0, 0, 0,       // zabuton（世代別）
  ]);

  return { id, timestamp: now };
}

/** 投稿編集 */
function actionEditPost(payload) {
  const { postId, type, phrases, comment, generation, sessionId } = payload;

  validateType(type);
  validatePhrases(type, phrases);
  validateGeneration(generation);
  const cleanComment   = sanitizeText(comment || "", MAX_COMMENT_LEN);
  const cleanSessionId = validateSessionId(sessionId);

  const { sheet, rowIndex } = findRowByIdAndSession(postId, cleanSessionId);

  // 編集可能フィールドのみ更新
  sheet.getRange(rowIndex, COL.TYPE).setValue(type);
  sheet.getRange(rowIndex, COL.PHRASES).setValue(
    JSON.stringify(phrases.map(p => sanitizeText(p, MAX_PHRASE_LEN)))
  );
  sheet.getRange(rowIndex, COL.COMMENT).setValue(cleanComment);
  sheet.getRange(rowIndex, COL.GENERATION).setValue(generation);

  return { ok: true };
}

/** 投稿削除 */
function actionDeletePost(payload) {
  const { postId, sessionId } = payload;
  const cleanSessionId = validateSessionId(sessionId);

  const { sheet, rowIndex } = findRowByIdAndSession(postId, cleanSessionId);
  sheet.deleteRow(rowIndex);

  return { ok: true };
}

/** 座布団（いいね） */
function actionZabuton(payload) {
  const { postId, generation } = payload;
  validateGeneration(generation);

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

  // 更新後の座布団数を返す
  const row = sheet.getRange(rowIndex, 1, 1, TOTAL_COLS).getValues()[0];
  return {
    zabuton: {
      teen:     Number(row[COL.ZAB_TEEN - 1]),
      twenties: Number(row[COL.ZAB_TWENTY - 1]),
      forties:  Number(row[COL.ZAB_FORTY - 1]),
      senior:   Number(row[COL.ZAB_SENIOR - 1]),
    }
  };
}

/* ============================================================
   ヘルパー関数
   ============================================================ */

function getSheet() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) {
    // シートが存在しなければ自動作成
    sheet = ss.insertSheet(SHEET_NAME);
    sheet.appendRow([
      "id","type","phrases","comment","generation",
      "session_id","timestamp",
      "zab_teen","zab_twenties","zab_forties","zab_senior"
    ]);
    sheet.setFrozenRows(1);
    // session_id 列を非表示（外部ツールから見えにくくする）
    sheet.hideColumns(COL.SESSION_ID);
  }
  return sheet;
}

/** 行データ → クライアントに返すオブジェクト（session_id を除外） */
function rowToPublicPost(row) {
  let phrases = [];
  try { phrases = JSON.parse(row[COL.PHRASES - 1]); } catch (_) {}

  return {
    id:         String(row[COL.ID - 1]),
    type:       String(row[COL.TYPE - 1]),
    phrases:    phrases,
    comment:    String(row[COL.COMMENT - 1] || ""),
    generation: String(row[COL.GENERATION - 1]),
    timestamp:  Number(row[COL.TIMESTAMP - 1]),
    zabuton: {
      teen:     Number(row[COL.ZAB_TEEN - 1]   || 0),
      twenties: Number(row[COL.ZAB_TWENTY - 1] || 0),
      forties:  Number(row[COL.ZAB_FORTY - 1]  || 0),
      senior:   Number(row[COL.ZAB_SENIOR - 1] || 0),
    },
    // session_id は絶対に返さない
  };
}

/** IDでスプレッドシートの行番号を返す（見つからなければ null） */
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

/** IDとSessionIdの両方が一致する行を返す（権限チェック） */
function findRowByIdAndSession(postId, sessionId) {
  const sheet    = getSheet();
  const rowIndex = findRowById(sheet, postId);
  if (!rowIndex) throw new AppError("投稿が見つかりません");

  const storedSession = String(
    sheet.getRange(rowIndex, COL.SESSION_ID).getValue()
  );
  if (storedSession !== sessionId) {
    throw new AppError("編集・削除の権限がありません");
  }
  return { sheet, rowIndex };
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

function validateSessionId(sessionId) {
  if (typeof sessionId !== "string") throw new AppError("セッションIDが不正です");
  // UUID v4 形式チェック
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!UUID_RE.test(sessionId)) throw new AppError("セッションIDの形式が不正です");
  return sessionId;
}

/** 文字列のサニタイズ（制御文字除去・長さ制限） */
function sanitizeText(str, maxLen) {
  if (typeof str !== "string") return "";
  // 制御文字（タブ・改行以外）を除去
  return str.replace(/[^\S\n\t]/g, " ").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").slice(0, maxLen).trim();
}
