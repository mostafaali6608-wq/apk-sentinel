export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

export type ScanFinding = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  summary: string;
  evidence: string;
  impact: string;
  fix: string;
  learning: string;
  verification: string;
  references: string[];
  attackSurface: string;
  confidence: Confidence;
  file: string;
};

export type ScanReport = {
  fileName: string;
  sizeBytes: number;
  scannedFiles: number;
  totalFiles: number;
  findings: ScanFinding[];
  categories: string[];
  durationMs: number;
  createdAt: string;
  rulesEvaluated: number;
  matchedRules: number;
  scannedBytes: number;
  limitations: string[];
};

type Rule = Omit<ScanFinding, 'evidence' | 'file'> & {
  pattern: RegExp;
  evidenceLabel?: string;
};

const rule = (
  id: string,
  title: string,
  severity: Severity,
  categoryOrPattern: string | RegExp,
  patternOrSummary: RegExp | string,
  summaryOrImpact: string,
  impactOrFix: string,
  fixOrLearning: string,
  maybeLearning?: string,
): Rule => {
  const hasCategory = typeof categoryOrPattern === 'string';
  const category = hasCategory ? categoryOrPattern : 'مراجعة عامة';
  const pattern = (hasCategory ? patternOrSummary : categoryOrPattern) as RegExp;
  const summary = hasCategory ? summaryOrImpact : patternOrSummary as string;
  const impact = hasCategory ? impactOrFix : summaryOrImpact;
  const fix = hasCategory ? fixOrLearning : impactOrFix;
  const learning = hasCategory ? maybeLearning ?? '' : fixOrLearning;
  return {
  id,
  title,
  severity,
  category,
  pattern,
  summary,
  impact,
  fix,
  learning,
   verification: `التحقق: راجع السياق حول المؤشر في ${title}، ثم اختبر النسخة الموقعة بسلوك متوقع وآمن قبل الإصدار.`,
   references: ['OWASP MASVS', 'OWASP MASTG', category],
   attackSurface: category,
   confidence: 'medium',
  };
};

const RULES: Rule[] = [
  rule('private-key', 'مفتاح خاص داخل الحزمة', 'critical', 'أسرار', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i, 'تم العثور على بداية مفتاح خاص.', 'قد يسمح بتوقيع أو فك تشفير أو انتحال هوية خدمة.', 'أزل المفتاح من التطبيق ودوّر المفتاح المتأثر فورًا، ثم استخدم مخزن أسرار في CI.', 'مسار التهديد: تسريب أصل تشفيري → انتحال الخدمة → فقدان الثقة.'),
  rule('aws-key', 'مفتاح AWS محتمل', 'critical', /\bAKIA[0-9A-Z]{16}\b/, 'سلسلة تشبه Access Key ثابتة.', 'قد تفتح موارد سحابية أو بيانات تخزين خارج التطبيق.', 'أوقف المفتاح ودوّره، ثم طبّق صلاحيات أقل ووسيطًا خلفيًا.', 'مسار التهديد: سر ثابت → وصول سحابي → استخراج بيانات أو تكلفة غير مصرح بها.'),
  rule('github-token', 'رمز GitHub داخل الملف', 'critical', /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/i, 'سلسلة تشبه رمز وصول GitHub.', 'يمكن استخدامها للوصول إلى مستودعات أو CI/CD.', 'ألغِ الرمز ودوّره، واجعل الوصول عبر بيئة البناء فقط.', 'مسار التهديد: رمز مستودع → تعديل سلسلة التوريد → تحديث خبيث للمستخدمين.'),
  rule('telegram-token', 'Telegram Bot Token', 'high', /\b\d{8,12}:[A-Za-z0-9_-]{35}\b/, 'تم العثور على صيغة رمز بوت Telegram.', 'قد يسمح بإرسال رسائل أو قراءة تحديثات البوت.', 'ألغِ الرمز من BotFather واحتفظ به على خادم لا داخل APK.', 'مسار التهديد: رمز بوت → انتحال البوت → احتيال أو تسريب محادثات.'),
  rule('generic-secret', 'سر أو كلمة مرور ثابتة', 'high', /(?:api[_-]?key|secret|password|client[_-]?secret)\s*["'=:\s]+\s*[A-Za-z0-9_./+=-]{12,}/i, 'اسم متغير حساس مرتبط بقيمة ثابتة.', 'يسهل استخراج الاعتماد من الحزمة وإعادة استخدامه.', 'استخدم رمزًا قصير العمر من خادم وامنع أسرار الإنتاج في العميل.', 'مسار التهديد: تحليل ثابت → استخراج سر → وصول غير مصرح.'),
  rule('jwt', 'JWT ثابت داخل الحزمة', 'high', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, 'تم العثور على بنية JWT.', 'قد تكون جلسة أو رمز خدمة قابلًا لإعادة الاستخدام.', 'لا تضع جلسات في الموارد؛ استخدم تخزينًا آمنًا وتحققًا قصير العمر.', 'مسار التهديد: تسريب جلسة → إعادة استخدام الرمز → انتحال حساب.'),
  rule('slack-token', 'رمز Slack محتمل', 'high', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/i, 'سلسلة تشبه رمز Slack.', 'قد تمنح وصولًا إلى مساحة عمل أو رسائل.', 'ألغِ الرمز ودوّره وامنعه من ملفات الموارد.', 'مسار التهديد: رمز مراسلة → قراءة أو إرسال رسائل → هندسة اجتماعية.'),
  rule('http-url', 'اتصال HTTP غير مشفر', 'high', /\bhttp:\/\/(?!localhost|127\.0\.0\.1)/i, 'رابط HTTP غير محلي.', 'يمكن اعتراض البيانات أو تعديل الاستجابة على الشبكة.', 'استخدم HTTPS مع تحقق صحيح من الشهادة وامنع cleartext.', 'مسار التهديد: شبكة غير موثوقة → اعتراض/تعديل → سرقة جلسة أو بيانات.'),
  rule('trust-all-tls', 'قبول كل شهادات TLS', 'critical', /(?:TrustAll|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})/i, 'مؤشر على تجاهل تحقق الشهادة أو اسم المضيف.', 'يسمح بهجوم الوسيط حتى على قناة تبدو آمنة.', 'احذف TrustManager المخصص واستخدم تحقق النظام واختبارات شهادة صحيحة.', 'مسار التهديد: شهادة مزيفة → MITM → قراءة أو تعديل الطلبات.'),
  rule('hostname-verifier', 'HostnameVerifier غير آمن', 'high', /HostnameVerifier|verify\s*\([^)]*\)\s*\{\s*return\s+true/i, 'تم العثور على تحقق اسم مضيف مخصص أو يعيد true.', 'قد يقبل اتصالًا بخادم غير صحيح.', 'اترك التحقق الافتراضي أو قارن اسم المضيف بقواعد موثوقة.', 'مسار التهديد: اسم مضيف مزور → جلسة مع مهاجم → تسريب الرموز.'),
  rule('cleartext-config', 'سياسة cleartext مفعلة', 'high', /usesCleartextTraffic\s*=\s*["']?true|cleartextTrafficPermitted\s*=\s*["']?true/i, 'إعداد يسمح بمرور نص صريح.', 'أي طلب HTTP قد يصبح قابلًا للاعتراض.', 'عطّل cleartext وأضف استثناءات ضيقة للتطوير فقط.', 'مسار التهديد: إعداد عام → قناة ضعيفة → اعتراض بيانات.'),
  rule('debuggable', 'نسخة قابلة للتصحيح', 'high', /android:debuggable\s*=\s*["']true["']|debuggable\s*=\s*true/i, 'علامة debuggable موجودة في الموارد.', 'تزيد قدرة التحليل والتلاعب على نسخة الإنتاج.', 'أزلها من release وتحقق من إعدادات Gradle وCI.', 'مسار التهديد: build خاطئ → أدوات تصحيح → استخراج أسرار أو منطق.'),
  rule('backup-enabled', 'نسخ احتياطي لبيانات التطبيق', 'medium', /android:allowBackup\s*=\s*["']true["']|android:fullBackupContent/i, 'السماح بالنسخ الاحتياطي مفعّل.', 'قد تنتقل بيانات حساسة خارج جهاز المستخدم.', 'عطّل النسخ أو استبعد الملفات الحساسة وفق سياسة المنتج.', 'مسار التهديد: نسخة احتياطية → استخراج بيانات محلية → كشف خصوصية.'),
  rule('exported-component', 'مكوّن Android مُصدّر', 'high', /android:exported\s*=\s*["']true["']|exported\s*=\s*true/i, 'مكوّن متاح لتطبيقات أخرى.', 'قد يسمح بتشغيل شاشة أو خدمة دون تحقق صلاحيات.', 'اجعل exported=false افتراضيًا وأضف تحققًا لصلاحيات كل intent.', 'مسار التهديد: تطبيق آخر → Intent خارجي → تنفيذ وظيفة محمية.'),
  rule('deep-link', 'رابط عميق غير مقيّد', 'medium', /(?:intent-filter|android:scheme|deepLink|Linking\.addEventListener)/i, 'تم العثور على تعامل مع Deep Link.', 'قد يقود إدخال غير موثوق إلى شاشة حساسة أو رابط خارجي.', 'تحقق من النطاق والمعلمات ولا تضع رموزًا في الرابط.', 'مسار التهديد: رابط مزور → شاشة حساسة → تصيد أو تنفيذ إجراء غير مقصود.'),
  rule('webview-js', 'JavaScript مفعّل في WebView', 'high', /setJavaScriptEnabled\s*\(\s*true\s*\)|javaScriptEnabled\s*[:=]\s*true/i, 'WebView يسمح بتشغيل JavaScript.', 'قد ينفذ محتوى غير موثوق أو يوسّع سطح الهجوم.', 'عطّل JavaScript افتراضيًا واسمح بقائمة نطاقات موثوقة فقط.', 'مسار التهديد: محتوى خارجي → JavaScript → سرقة جلسة أو جسر أصلي.'),
  rule('webview-bridge', 'جسر JavaScript أصلي', 'critical', /addJavascriptInterface|postMessage\s*\(/i, 'جسر بين صفحة الويب والكود الأصلي.', 'قد يحول XSS إلى صلاحيات داخل التطبيق.', 'قلّل الدوال المكشوفة، تحقق من origin، ولا تقبل محتوى غير موثوق.', 'مسار التهديد: صفحة محقونة → bridge → وظائف أصلية حساسة.'),
  rule('file-access-webview', 'وصول ملفات من WebView', 'high', /setAllowFileAccess\s*\(\s*true\s*\)|allowFileAccess\s*[:=]\s*true/i, 'WebView يستطيع قراءة ملفات محلية.', 'قد يسرّب موارد أو ملفات جلسة إلى محتوى ويب.', 'عطّل file access واسمح بمسارات محددة عند الضرورة.', 'مسار التهديد: صفحة ويب → قراءة ملف محلي → كشف أسرار.'),
  rule('local-storage', 'تخزين حساس غير آمن محتمل', 'high', /SharedPreferences|AsyncStorage|localStorage|NSUserDefaults/i, 'استخدام مخزن عام داخل التطبيق.', 'الجلسات والأسرار قد تبقى قابلة للاستخراج.', 'استخدم Keychain/Keystore للرموز وشفّر البيانات الحساسة.', 'مسار التهديد: تحليل جهاز/نسخة احتياطية → قراءة مخزن → إعادة استخدام جلسة.'),
  rule('clipboard', 'نسخ أسرار إلى الحافظة', 'medium', /Clipboard|setPrimaryClip|copyToClipboard/i, 'استخدام الحافظة مع محتوى قد يكون حساسًا.', 'تطبيقات أخرى قد تقرأ الحافظة أو تبقى البيانات مدة طويلة.', 'امنع نسخ الأسرار أو امسح الحافظة بعد مدة قصيرة مع تنبيه المستخدم.', 'مسار التهديد: رمز في الحافظة → تطبيق آخر → كشف اعتماد.'),
  rule('screenshot', 'لقطات شاشة غير محمية', 'medium', /FLAG_SECURE|allowScreenCapture|screenCapture/i, 'مؤشرات التقاط أو حماية الشاشة.', 'قد تظهر رموز أو بيانات خاصة في اللقطات أو التطبيقات الحديثة.', 'فعّل FLAG_SECURE للشاشات الحساسة وامنع التسجيل عند الحاجة.', 'مسار التهديد: شاشة حساسة → لقطة/تسجيل → كشف بيانات.'),
  rule('md5', 'استخدام MD5', 'high', /\bMD5\b|MessageDigest\.getInstance\s*\(\s*["']MD5/i, 'خوارزمية تجزئة قديمة وضعيفة للتوقيعات الأمنية.', 'التصادمات تسهّل التلاعب عندما تستخدم للتحقق الأمني.', 'استخدم SHA-256 أو توقيعًا حديثًا حسب الغرض.', 'مسار التهديد: تجزئة ضعيفة → ملف بديل → تجاوز تحقق سلامة.'),
  rule('sha1', 'استخدام SHA-1', 'medium', /\bSHA-?1\b|MessageDigest\.getInstance\s*\(\s*["']SHA-1/i, 'خوارزمية متقادمة.', 'لم تعد مناسبة لضمان سلامة قوية.', 'استخدم SHA-256 أو أقوى مع إدارة مفاتيح صحيحة.', 'مسار التهديد: تصادم/تحقق ضعيف → قبول محتوى معدل.'),
  rule('des', 'تشفير DES/3DES', 'high', /\b(?:DES|DESede|TripleDES)\b/i, 'خوارزمية تشفير قديمة.', 'قد تضعف سرية البيانات أو توافق المستقبل.', 'استخدم AES-GCM أو ChaCha20-Poly1305 مع nonce عشوائي.', 'مسار التهديد: تشفير ضعيف → فك أسرع/هجوم تحليل → كشف بيانات.'),
  rule('ecb', 'وضع AES-ECB', 'high', /AES\/ECB|Cipher\.getInstance\s*\(\s*["']AES["']/i, 'وضع تشفير يكشف الأنماط أو دون مصادقة.', 'قد يسمح بتسريب بنية البيانات أو قبول تعديل صامت.', 'استخدم AES-GCM مع إدارة nonce ومصادقة النص.', 'مسار التهديد: نمط مكشوف/تعديل → قراءة أو تغيير بيانات محلية.'),
  rule('hardcoded-iv', 'IV أو nonce ثابت', 'high', /(?:iv|nonce|initializationVector)\s*=\s*["'][A-Za-z0-9+/=_-]{8,}["']/i, 'قيمة IV/nonce ثابتة داخل المصدر.', 'إعادة استخدام nonce تكسر ضمانات بعض أوضاع التشفير.', 'ولّد nonce عشوائيًا لكل عملية وخزّنه مع ciphertext.', 'مسار التهديد: nonce معاد الاستخدام → تسريب علاقة النصوص → كشف بيانات.'),
  rule('weak-rsa', 'مفتاح RSA قصير', 'high', /RSA[^\n]{0,80}(?:512|768|1024)|keySize\s*=\s*(?:512|768|1024)/i, 'مؤشر على حجم مفتاح غير مناسب.', 'تقل مقاومة المفتاح للكسر مقارنة بالحدود الحديثة.', 'استخدم RSA-2048 أو ECC حديثًا وفق سياسة المنصة.', 'مسار التهديد: مفتاح ضعيف → كسر/انتحال → فك أو توقيع.'),
  rule('insecure-random', 'مولد عشوائي غير تشفيري', 'medium', /new\s+Random\s*\(|Math\.random\s*\(/i, 'عشوائية عامة قرب سياق أمني.', 'قد يمكن توقع الرموز أو المعرفات الحساسة.', 'استخدم SecureRandom أو مصدرًا تشفيريًا مناسبًا للرموز.', 'مسار التهديد: توقع رمز → إعادة استخدام → تجاوز جلسة أو رابط.'),
  rule('logs', 'تسجيل بيانات في السجلات', 'medium', /Log\.[divew]\s*\(|console\.log\s*\(|printStackTrace\s*\(/i, 'نداء تسجيل قد يطبع بيانات تشغيلية.', 'قد تظهر رموز أو معلومات شخصية في سجلات الجهاز.', 'أزل السجلات الحساسة من release واستخدم redaction.', 'مسار التهديد: سجل مكشوف → قراءة محلية/عن بعد → كشف بيانات.'),
  rule('test-endpoint', 'نقطة اختبار أو staging', 'medium', /(?:staging|dev|localhost|127\.0\.0\.1|10\.0\.2\.2)/i, 'عنوان تطوير أو اختبار داخل الحزمة.', 'قد يوجه النسخة للمسار الخطأ أو يكشف بيئة داخلية.', 'افصل إعدادات البيئات وتحقق من build variant قبل الإصدار.', 'مسار التهديد: إعداد اختبار → بيئة أضعف → وصول أو بيانات غير صحيحة.'),
  rule('firebase-config', 'إعداد Firebase داخل التطبيق', 'info', 'سلسلة supply chain/خدمة.', /google_app_id|firebase_database_url|project_id/i, 'تم العثور على إعداد Firebase.', 'ليس سرًا وحده، لكنه يحتاج قواعد Firebase ومفاتيح API مقيدة.', 'راجع قواعد Firestore/Storage وقيد المفاتيح حسب الحزمة والنطاق.', 'مسار التهديد: إعداد عام + قواعد ضعيفة → قراءة/تعديل بيانات.'),
  rule('sentry-dsn', 'Sentry DSN مكشوف', 'low', /https?:\/\/[a-f0-9]{16,}@[^/]+\/\d+/i, 'عنوان DSN لتقارير الأخطاء.', 'قد يسمح بإرسال ضوضاء أو بيانات إلى مشروع المراقبة.', 'قيد DSN على العميل وامنع إرسال PII ونظّف breadcrumbs.', 'مسار التهديد: DSN عام → إغراق التقارير → إخفاء حادث أو تكلفة.'),
  rule('source-map', 'Source map داخل الإصدار', 'medium', /\.map["']?\s*[:=]|sourceMappingURL=/i, 'ملف أو رابط source map ضمن الموارد.', 'يكشف أسماء الدوال والمنطق الداخلي بسهولة.', 'احذف source maps من release أو احفظها في منصة خاصة.', 'مسار التهديد: خريطة مصدر → فهم المنطق → استهداف نقاط حساسة.'),
  rule('billing-local-flag', 'منطق اشتراك محلي قابل للتلاعب', 'critical', /(?:isPremium|isPro|premium\s*[:=]\s*true|vip|unlocked)/i, 'مؤشر على قرار صلاحية محلي.', 'قد يسمح بتغيير القيمة محليًا للوصول إلى ميزات مدفوعة.', 'اجعل الخادم مصدر الحقيقة وتحقق من الإيصال أو entitlement.', 'مسار التهديد: تعديل قرار محلي → تفعيل ميزة → خسارة إيراد.'),
  rule('billing', 'Billing أو IAP داخل التطبيق', 'high', /(?:BillingClient|InAppPurchase|purchaseUpdated|StoreKit|RevenueCat|Stripe)/i, 'تم العثور على منطق شراء أو اشتراك.', 'التحقق المحلي وحده لا يكفي لحماية entitlement.', 'تحقق من الإيصالات على الخادم واربطها بحساب ومكافحة replay.', 'مسار التهديد: اعتراض نتيجة شراء → entitlement مزيف → فقدان إيراد.'),
  rule('receipt-client', 'تحقق إيصال على العميل', 'high', /(?:verifyReceipt|validateReceipt|receiptData)\s*[\(:=]/i, 'يبدو أن التحقق من الإيصال داخل العميل.', 'يمكن تعديل تدفق العميل أو منع طلب التحقق.', 'انقل التحقق إلى خادم موثوق وسجّل حالة الاشتراك server-side.', 'مسار التهديد: تعديل client flow → قبول إيصال مزيف → وصول مدفوع.'),
  rule('play-integrity', 'لا يظهر Play Integrity قرب Billing', 'medium', /(?:BillingClient|purchaseUpdated|InAppPurchase)/i, 'شراء موجود دون مؤشر Play Integrity في نفس المحتوى.', 'تقل إشارة الثقة ضد بيئات معدلة أو replay.', 'أضف Play Integrity على الخادم كإشارة مساعدة، لا كبديل للتحقق من الإيصال.', 'مسار التهديد: بيئة معدلة → طلب شراء مزور → قرار اشتراك غير صحيح.'),
  rule('telegram-webhook', 'Telegram webhook داخل التطبيق', 'high', /api\.telegram\.org\/bot|setWebhook|sendMessage/i, 'تم العثور على استدعاء Telegram API.', 'قد يكشف رمز البوت أو يسمح بانتحال قناة التنبيه.', 'اجعل Telegram خلف API خاص ولا تخزن رمز البوت في العميل.', 'مسار التهديد: API مباشر → استخراج الرمز → إرسال رسائل احتيالية.'),
  rule('dangerous-permission', 'صلاحية حساسة مطلوبة', 'medium', /(?:READ_SMS|RECEIVE_SMS|SEND_SMS|READ_CONTACTS|READ_CALL_LOG|RECORD_AUDIO)/i, 'تم العثور على صلاحية عالية الحساسية.', 'تزيد أثر أي خلل أو إساءة استخدام داخل التطبيق.', 'اطلب أقل صلاحية وفي السياق، ووثّق السبب وراجعها مع سياسة الخصوصية.', 'مسار التهديد: صلاحية واسعة → تسريب/إساءة استخدام → أثر خصوصية مرتفع.'),
  rule('location-permission', 'صلاحية موقع', 'low', /(?:ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|requestLocation)/i, 'التطبيق يتعامل مع موقع المستخدم.', 'قد يكشف الموقع عند الجمع أو التخزين غير المنضبط.', 'اجمعه عند الحاجة فقط وشفّر النقل ووضح الاحتفاظ.', 'مسار التهديد: جمع زائد → ربط هوية وموقع → كشف خصوصية.'),
  rule('camera-permission', 'صلاحية الكاميرا', 'low', /(?:CAMERA|ImagePicker|CameraView)/i, 'التطبيق يتعامل مع الكاميرا أو الصور.', 'قد يتسع أثر أي خلل في مسار رفع الصور.', 'تحقق من نوع وحجم الملف وامنع رفعًا مباشرًا إلى نطاق غير موثوق.', 'مسار التهديد: ملف/صورة غير موثوقة → معالجة ضعيفة → تسريب أو تنفيذ.'),
  rule('overlay', 'صلاحية الرسم فوق التطبيقات', 'high', /SYSTEM_ALERT_WINDOW|drawOverlays|TYPE_APPLICATION_OVERLAY/i, 'صلاحية تسمح بطبقة فوق تطبيقات أخرى.', 'قد تستخدم للتصيد أو حجب شاشات النظام.', 'لا تطلبها إلا لسبب واضح وراقب إساءة استخدامها.', 'مسار التهديد: overlay → واجهة مزورة → سرقة اعتماد.'),
  rule('accessibility', 'استخدام Accessibility Service', 'high', /AccessibilityService|BIND_ACCESSIBILITY_SERVICE/i, 'خدمة وصول حساسة مذكورة.', 'قد تقرأ محتوى شاشات أخرى أو تنفذ إجراءات واسعة.', 'قيدها على حالة استخدام موثقة وتحقق من كل أمر وارد.', 'مسار التهديد: خدمة واسعة → قراءة شاشة/ضغط آلي → سرقة حساب.'),
  rule('package-visibility', 'رؤية واسعة للتطبيقات المثبتة', 'medium', /QUERY_ALL_PACKAGES|queryIntentActivities/i, 'التطبيق قد يجمع قائمة التطبيقات.', 'قد يكشف سمات حساسة عن المستخدم أو يوسع السطح.', 'استخدم استعلامات محددة للغرض المعلن فقط.', 'مسار التهديد: بصمة تطبيقات → استنتاج هوية/حالة → استهداف.'),
  rule('root-detection', 'مؤشرات فحص Root/Emulator', 'info', /(?:isRooted|SafetyNet|PlayIntegrity|Emulator|Magisk|su\b)/i, 'التطبيق يحتوي على منطق بيئة أو سلامة.', 'الفحص وحده ليس ضمانًا ويمكن أن يعطي ثقة زائفة.', 'اعتبره إشارة telemetry، واجعل الحماية الحقيقية server-side.', 'مسار التهديد: إشارة محلية قابلة للتجاوز → ثقة زائفة → قرار حماية غير صحيح.'),
  rule('frida', 'مؤشرات Anti-Frida/Instrumentation', 'info', /(?:Frida|gum-js-loop|frida-server|Xposed|Substrate)/i, 'تم العثور على اسم أداة instrumentation أو مقاومة لها.', 'قد يحاول التطبيق الاعتماد على مقاومة محلية قابلة للتجاوز.', 'استخدم attestation وقرارات خادم وراقب السلوك بدل الاعتماد على كشف اسم أداة.', 'مسار التهديد: كشف محلي → تجاوز/تغيير سلوك → فشل قرار الحماية.'),
  rule('packer', 'مؤشر حماية أو Packer', 'info', /(?:Jiagu|SecNeo|DexProtector|Bangcle|Tencent\s*Legu|libshell|libjiagu)/i, 'مكتبة أو اسم شائع في Packers.', 'قد يصعّب التدقيق ويخفي سلوكًا أو يزيد تعقيد الاستجابة للحوادث.', 'وثّق أداة التغليف، افحص release بعد التغليف، واحتفظ بخرائط رموز آمنة.', 'مسار التهديد: سلسلة بناء غير شفافة → صعوبة تدقيق → تأخر اكتشاف خلل.'),
  rule('native-library', 'مكتبات Native تحتاج مراجعة', 'low', /\.so["']?$|lib\/(?:arm64-v8a|armeabi-v7a|x86_64)\//i, 'تم العثور على مكتبة Native.', 'الكود الأصلي يزيد صعوبة التحليل وقد يخفي تعاملًا مع الذاكرة.', 'افحص ABI، الرموز، الحدود، وفعّل hardening في NDK.', 'مسار التهديد: خطأ ذاكرة Native → تحكم في التنفيذ → تسريب أو تصعيد.'),
  rule('unsafe-deserialization', 'إلغاء تسلسل غير آمن محتمل', 'high', /(?:ObjectInputStream|readObject\s*\(|pickle|unserialize|NSKeyedUnarchiver)/i, 'استخدام API لإلغاء تسلسل قد يستقبل بيانات خارجية.', 'قد ينفذ منطقًا أو يخلق كائنات غير متوقعة.', 'استخدم صيغًا آمنة ومخططات صارمة ولا تقبل كائنات عامة.', 'مسار التهديد: مدخل معدل → كائن غير متوقع → تنفيذ أو تجاوز منطق.'),
  rule('sql-concat', 'استعلام SQL مبني بضم نصي', 'high', /(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]{0,100}\+\s*[A-Za-z_]/i, 'مؤشر على ضم قيمة داخل استعلام.', 'قد يسمح بحقن استعلام عند وصول مدخل غير موثوق.', 'استخدم معاملات prepared statements وقيودًا على الإدخال.', 'مسار التهديد: مدخل غير موثوق → استعلام معدل → قراءة/تغيير بيانات.'),
  rule('path-traversal', 'تجميع مسار من مدخل خارجي', 'high', /(?:\.\.\/|\.\.\\\\|File\s*\([^)]*\+|resolve\s*\([^)]*\+)/i, 'مؤشر على traversal أو مسار ديناميكي.', 'قد يصل إلى ملفات خارج المجلد المقصود.', 'طبّع المسار، استخدم allowlist، وقيّد root directory.', 'مسار التهديد: اسم ملف معدل → خروج من المجلد → قراءة ملف حساس.'),
  rule('open-redirect', 'إعادة توجيه أو فتح رابط خارجي', 'medium', /(?:openURL|startActivity|ACTION_VIEW|redirectUrl|returnUrl)/i, 'تعامل مع رابط خارجي أو redirect.', 'قد يستخدم في تصيد أو سرقة رمز عبر رابط غير موثوق.', 'قيد النطاقات وتحقق من scheme وhost قبل الفتح.', 'مسار التهديد: رابط غير موثوق → تصيد/تسريب callback → سرقة جلسة.'),
  rule('custom-scheme', 'Custom URL Scheme عام', 'medium', /(?:URLScheme|CFBundleURLSchemes|android:scheme|Linking\.openURL)/i, 'رابط مخصص يمكن لتطبيق آخر اعتراضه.', 'قد يعترض تطبيق آخر callback أو يرسل قيمًا مزورة.', 'استخدم App/Universal Links مع تحقق state وPKCE.', 'مسار التهديد: اعتراض callback → تبديل state → ربط حساب خاطئ.'),
  rule('oauth-implicit', 'OAuth ضمن العميل دون مؤشرات PKCE', 'high', /(?:client_id|authorization_code|access_token|oauth)/i, 'مؤشرات تدفق OAuth في الحزمة.', 'قد تتسرب الرموز أو يستخدم تدفق غير مناسب لتطبيق عام.', 'استخدم Authorization Code + PKCE ولا تضع client secret في العميل.', 'مسار التهديد: عميل عام → سر غير قابل للحماية → انتحال أو اعتراض رمز.'),
  rule('analytics-id', 'معرّف إعلاني أو جهاز', 'medium', /(?:AdvertisingIdClient|ANDROID_ID|IDFA|deviceId|installationId)/i, 'جمع معرّف ثابت أو شبه ثابت.', 'قد يربط نشاط المستخدم عبر خدمات أو جلسات.', 'قلل الجمع، اعرض الإفصاح، واسمح بإعادة الضبط وعدم التتبع.', 'مسار التهديد: معرّف ثابت → ربط سلوك → كشف خصوصية.'),
  rule('health-data', 'بيانات صحية أو حساسة', 'high', /(?:health|medical|diagnosis|biometric|fingerprint|faceId)/i, 'مصطلح حساس ظهر في المحتوى.', 'رفع أو تخزين غير منضبط قد يسبب أثرًا تنظيميًا وخصوصيًا.', 'قلل البيانات وشفّرها وحدد الاحتفاظ والصلاحيات.', 'مسار التهديد: بيانات حساسة → وصول زائد → ضرر خصوصية/تنظيم.'),
  rule('backup-logs', 'ملفات سجل أو dump ضمن الحزمة', 'medium', /(?:\.log$|crash_dump|heapdump|mapping\.txt|proguard\.map)/i, 'ملف تشخيصي أو خريطة رموز موجودة.', 'قد تكشف مسارات أو رموزًا أو بيانات اختبار.', 'احذفها من release واحتفظ بها في تخزين CI مقيد.', 'مسار التهديد: artifact تشخيصي → كشف بنية → تسهيل استهداف.'),
  rule('unsigned-debug', 'توقيع أو شهادة اختبار محتملة', 'high', /(?:debug\.keystore|AndroidDebugKey|CN=Android Debug)/i, 'مؤشر على شهادة تطوير.', 'قد يسمح بتثبيت أو تحديث غير موثوق في بعض السيناريوهات.', 'تحقق من شهادة release ووقّع عبر CI محمي.', 'مسار التهديد: توقيع اختبار → تحديث مزور → استبدال التطبيق.'),
  rule('hardcoded-url', 'نقطة API ثابتة تحتاج مراجعة', 'low', /https?:\/\/[A-Za-z0-9.-]+\/(?:api|v\d|graphql|oauth)/i, 'تم العثور على endpoint داخل العميل.', 'الـ endpoint ليس سرًا لكن يحتاج TLS وسياسة مصادقة صحيحة.', 'استخدم إعدادات بيئة مضبوطة ولا تعتمد على إخفاء الرابط.', 'مسار التهديد: endpoint مكشوف → استكشاف API → إساءة استخدام إذا غابت المصادقة.'),
  rule('weak-session', 'جلسة طويلة أو رمز في query string', 'high', /(?:token|session|auth)[^=\n]{0,20}=[^&\s]{12,}|[?&](?:token|key|auth)=/i, 'رمز محتمل في رابط أو قيمة ثابتة.', 'قد يظهر في سجلات أو analytics أو clipboard.', 'استخدم Authorization header وروابط قصيرة العمر بلا أسرار.', 'مسار التهديد: رمز في URL → سجلات/إحالات → إعادة استخدام.'),
  rule('cors-wildcard', 'CORS عام محتمل', 'medium', /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']|cors\s*\(\s*\)/i, 'مؤشر على سياسة أصل واسعة.', 'قد تسمح لمواقع غير موثوقة بطلبات حساسة إن غابت حماية أخرى.', 'قيد origins وفعّل credentials فقط مع قائمة صريحة.', 'مسار التهديد: أصل مهاجم → طلب حساس → قراءة/تغيير بيانات.'),
];

const ADVANCED_RULES: Rule[] = [
  rule('manifest-task-affinity', 'Task affinity مخصص', 'medium', 'سطح Android', /android:taskAffinity\s*=\s*["'][^"']+["']/i, 'تم تخصيص علاقة المهمة مع تطبيقات أو مهام أخرى.', 'قد يسبب اختلاطًا بين المهام أو يسهّل انتحال شاشة عند بناء تدفق حساس.', 'اترك القيمة الافتراضية ما لم توجد حاجة موثقة، واختبر العودة من الروابط الخارجية.', 'مسار التهديد: مهمة مشتركة → شاشة مزورة أو تسريب سياق جلسة.'),
  rule('manifest-reparenting', 'إعادة إسناد المهام', 'medium', 'سطح Android', /android:allowTaskReparenting\s*=\s*["']true["']/i, 'إعادة إسناد النشاط إلى مهمة أخرى مفعلة.', 'قد يظهر محتوى حساس في سياق تطبيق غير متوقع.', 'عطّلها في الشاشات الحساسة واختبر دورة lifecycle بالكامل.', 'مسار التهديد: انتقال نشاط → ظهور في سياق خاطئ → كشف بيانات.'),
  rule('manifest-no-history', 'نشاط بلا تاريخ', 'low', 'سطح Android', /android:noHistory\s*=\s*["']true["']/i, 'النشاط لا يحتفظ بسجل العودة.', 'قد يربك تدفقات المصادقة أو يترك نتيجة حساسة دون حالة واضحة.', 'استخدمه فقط للتدفقات المؤقتة ووثّق أثره على المصادقة.', 'مسار التهديد: دورة رجوع غير متوقعة → تخطي خطوة تحقق أو فقدان تنبيه.'),
  rule('manifest-exclude-recents', 'استبعاد من التطبيقات الحديثة', 'low', 'سطح Android', /android:excludeFromRecents\s*=\s*["']true["']/i, 'الشاشة مستبعدة من قائمة التطبيقات الحديثة.', 'قد يخفي شاشة حساسة عن المستخدم أو يصعب عليه مراجعة جلسة مفتوحة.', 'استخدمه بحذر ولا تعتبره حماية للبيانات.', 'مسار التهديد: شاشة مخفية → جلسة متروكة → وصول محلي غير مقصود.'),
  rule('manifest-launch-mode', 'وضع تشغيل نشاط غير اعتيادي', 'medium', 'سطح Android', /android:launchMode\s*=\s*["'](?:singleTask|singleTop|singleInstance|singleInstancePerTask)["']/i, 'استخدام launchMode يغير إعادة استخدام النشاط.', 'قد يعيد تمرير intents أو رموز callback إلى حالة قديمة.', 'تحقق من onNewIntent ونظّف الحالة قبل معالجة كل رابط.', 'مسار التهديد: intent قديم → حالة جلسة خاطئة → ربط أو تنفيذ غير مقصود.'),
  rule('manifest-grant-uri', 'منح صلاحيات URI', 'high', 'سطح Android', /android:grantUriPermissions\s*=\s*["']true["']/i, 'السماح بمنح وصول مؤقت إلى URIs.', 'قد يصل تطبيق آخر إلى ملف خاص إذا لم تُقيّد URI والمدة.', 'استخدم FileProvider وURIs مؤقتة وقائمة MIME ضيقة.', 'مسار التهديد: URI قابل للمشاركة → تطبيق آخر → قراءة ملف خاص.'),
  rule('manifest-provider-exported', 'Content Provider مُصدّر', 'high', 'سطح Android', /<provider\b[^>]*android:exported\s*=\s*["']true["']/is, 'مزود محتوى متاح خارج التطبيق.', 'قد يقرأ أو يغيّر بيانات التطبيق إذا غابت صلاحية مخصصة.', 'اجعل provider غير مُصدّر أو احمِه بصلاحية signature مع تحقق المسار.', 'مسار التهديد: تطبيق آخر → provider → قراءة أو تعديل قاعدة بيانات.'),
  rule('manifest-receiver-exported', 'Broadcast Receiver مُصدّر', 'high', 'سطح Android', /<receiver\b[^>]*android:exported\s*=\s*["']true["']/is, 'مستقبل بث خارجي.', 'قد يستقبل أوامر مزورة أو يكرر حدثًا حساسًا.', 'قيّد receiver بصلاحية وفعّل التحقق من المصدر والnonce.', 'مسار التهديد: بث مزور → تنفيذ أمر → تغيير حالة أو تسريب.'),
  rule('manifest-service-exported', 'Service مُصدّرة', 'high', 'سطح Android', /<service\b[^>]*android:exported\s*=\s*["']true["']/is, 'خدمة يمكن لتطبيق آخر تشغيلها أو ربطها.', 'قد تعرض وظائف طويلة المدى أو بيانات دون تحقق هوية.', 'اجعلها غير مُصدّرة أو استخدم permission من نوع signature.', 'مسار التهديد: bind/start خارجي → خدمة محمية بلا تحقق → إساءة استخدام.'),
  rule('manifest-alias', 'Activity Alias يحتاج مراجعة', 'medium', 'سطح Android', /<activity-alias\b/i, 'وجود alias يضيف مدخلًا بديلًا للتطبيق.', 'قد يفتح شاشة دون نفس قيود النشاط الأصلي أو يربك deeplink.', 'راجع exported والـ intent filters لكل alias منفصلًا.', 'مسار التهديد: مدخل بديل → تجاوز قيد شاشة → وصول غير مقصود.'),
  rule('manifest-permission-protection', 'صلاحية بتصنيف ضعيف', 'high', 'سطح Android', /android:protectionLevel\s*=\s*["'](?:normal|dangerous)["']/i, 'تعريف صلاحية مخصصة ليست من نوع signature.', 'تطبيقات أخرى قد تطلبها أو تحصل عليها بسهولة أكبر من المتوقع.', 'استخدم signature للواجهات بين التطبيقات أو أزل الصلاحية غير الضرورية.', 'مسار التهديد: صلاحية واسعة → تطبيق آخر يحصل عليها → استدعاء API داخلي.'),
  rule('manifest-install-packages', 'تثبيت حزم أخرى', 'high', 'الصلاحيات', /REQUEST_INSTALL_PACKAGES|ACTION_INSTALL_PACKAGE/i, 'التطبيق يتعامل مع تثبيت حزم.', 'قد يستخدم لتثبيت نسخة غير موثوقة أو تجاوز مراجعة المتجر.', 'لا تطلبها إلا لسبب معلن، وتحقق من المصدر والتوقيع قبل أي تثبيت.', 'مسار التهديد: ملف APK خارجي → تثبيت بديل → استبدال أو تصعيد ثقة.'),
  rule('manifest-delete-packages', 'حذف حزم أخرى', 'high', 'الصلاحيات', /REQUEST_DELETE_PACKAGES|ACTION_DELETE_PACKAGE/i, 'التطبيق يطلب إزالة حزم.', 'قد يعطل أدوات الحماية أو يزيل تطبيقًا دون توقع المستخدم.', 'قيد الاستخدام بحالة إدارية موثقة واطلب تأكيدًا واضحًا.', 'مسار التهديد: أمر حذف → إزالة حماية أو تطبيق → فقدان السيطرة.'),
  rule('manifest-query-all', 'QUERY_ALL_PACKAGES مكرر', 'medium', 'الخصوصية', /QUERY_ALL_PACKAGES/i, 'صلاحية رؤية جميع التطبيقات مثبتة.', 'تخلق بصمة حساسة وقد تكون مخالفة لمتطلبات المتجر.', 'استبدلها باستعلامات package محددة للحالة المعلنة فقط.', 'مسار التهديد: بصمة تطبيقات → استنتاج سلوك المستخدم → استهداف.'),
  rule('manifest-request-legacy', 'تخزين خارجي legacy', 'medium', 'تخزين', /requestLegacyExternalStorage\s*=\s*["']true["']/i, 'التطبيق يطلب نمط التخزين القديم.', 'يزيد نطاق الوصول إلى ملفات مشتركة ويصعّب العزل.', 'استخدم scoped storage وMediaStore أو Storage Access Framework.', 'مسار التهديد: مجلد مشترك → ملف غير موثوق → قراءة أو استبدال.'),
  rule('manifest-network-config', 'Network Security Config مخصص', 'low', 'الشبكة', /android:networkSecurityConfig\s*=\s*["'][^"']+["']/i, 'تم تخصيص سياسة أمان الشبكة.', 'قد تحتوي السياسة على استثناءات debug أو شهادات مستخدم.', 'افحص XML المشار إليه، وافصل إعداد debug عن release.', 'مسار التهديد: استثناء شبكة → قبول شهادة غير موثوقة → MITM.'),
  rule('network-user-certificates', 'قبول شهادات المستخدم', 'high', 'الشبكة', /<certificates\s+src\s*=\s*["']user["']|src\s*=\s*["']user["']/i, 'سياسة الشبكة تقبل شهادات يثبتها المستخدم.', 'قد يسهّل اعتراض TLS على جهاز مراقب أو معدل.', 'امنع user CA في release إلا لاحتياج مؤسسي موثق مع ضوابط إضافية.', 'مسار التهديد: CA محلية → شهادة بديلة → قراءة أو تعديل المرور.'),
  rule('network-debug-overrides', 'استثناءات debug في release', 'high', /debug-overrides|overridePins\s*=\s*["']true["']/i, 'وجود استثناءات شهادات أو pinning خاصة بالتطوير.', 'قد تنتقل إعدادات التطوير إلى النسخة النهائية.', 'تحقق من variant والـ merged manifest في CI قبل النشر.', 'مسار التهديد: override debug → تجاوز pinning → MITM.'),
  rule('network-tls-old', 'إصدار TLS قديم', 'high', 'الشبكة', /TLSv1(?:\.0|\.1)?|SSLv3|PROTOCOL_TLSv1/i, 'استخدام إصدار تشفير قديم أو متوقف.', 'يقلل مقاومة القناة لهجمات معروفة وسياسات الخوادم الحديثة.', 'استخدم TLS 1.2 أو أحدث واترك التفاوض للنظام.', 'مسار التهديد: بروتوكول قديم → downgrade أو ضعف تشفير → كشف بيانات.'),
  rule('network-websocket-cleartext', 'WebSocket غير مشفر', 'high', 'الشبكة', /\bws:\/\/(?!localhost|127\.0\.0\.1)/i, 'قناة WebSocket غير مشفرة.', 'يمكن اعتراض الرسائل أو تعديلها أثناء الاتصال.', 'استخدم wss مع مصادقة ورسائل ذات nonce عند الحاجة.', 'مسار التهديد: قناة ws → اعتراض أمر/بيانات → تغيير حالة.'),
  rule('network-basic-auth', 'Basic Auth داخل التطبيق', 'high', 'المصادقة', /Authorization\s*:\s*Basic|Basic\s+[A-Za-z0-9+/=]{12,}/i, 'إرسال اعتماد بصيغة Basic.', 'يمكن كشف الاعتماد بسهولة عند اعتراض القناة أو السجلات.', 'استخدم رموزًا قصيرة العمر عبر HTTPS ودوّر الاعتماد عند الاشتباه.', 'مسار التهديد: Basic credential → اعتراض → دخول متكرر.'),
  rule('network-bearer-query', 'Bearer في رابط', 'high', 'الجلسات', /[?&](?:access_token|bearer|token)=/i, 'وضع رمز وصول في query string.', 'قد يظهر في السجلات والإحالات وanalytics.', 'استخدم Authorization header وامنع تسجيل headers الحساسة.', 'مسار التهديد: URL → سجل/إحالة → إعادة استخدام الرمز.'),
  rule('network-pinning-disabled', 'تعطيل Certificate Pinning', 'high', 'الشبكة', /(?:disable|skip|bypass|without)[A-Za-z0-9_\s-]{0,30}(?:pinning|certificate)/i, 'اسم أو مسار يوحي بتعطيل pinning.', 'قد يفقد التطبيق طبقة دفاع إضافية ضد MITM في حالات محددة.', 'اجعل التعطيل محصورًا في debug وتحقق آليًا من release.', 'مسار التهديد: flag تعطيل → قناة قابلة للمراقبة → سرقة جلسة.'),
  rule('network-proxy-config', 'Proxy أو وكيل مخصص', 'medium', 'الشبكة', /(?:ProxySelector|setProxy|HTTP_PROXY|proxyHost|proxyPort)/i, 'التطبيق يغير إعدادات الوكيل.', 'قد يرسل البيانات إلى وسيط غير مقصود أو يضعف التدقيق.', 'اسمح بالوكيل فقط في debug وسجّل سبب التغيير بوضوح.', 'مسار التهديد: وكيل غير موثوق → مراقبة/تعديل الطلبات → تسريب.'),
  rule('network-cookie-persistence', 'كوكيز جلسة دائمة', 'high', 'الجلسات', /CookieManager|setCookie|persistentCookie|NSHTTPCookieStorage/i, 'تخزين كوكيز جلسة داخل العميل.', 'قد تبقى الجلسة بعد تسجيل الخروج أو تنتقل إلى نسخة احتياطية.', 'اجعل الكوكيز Secure وHttpOnly وSameSite ونظّفها عند الخروج.', 'مسار التهديد: كوكيز باقية → استخراج محلي → انتحال جلسة.'),
  rule('network-retry-leak', 'إعادة محاولة قد تعيد إرسال سر', 'medium', 'الشبكة', /(?:retry|replay|repeat)[A-Za-z0-9_\s-]{0,30}(?:request|upload|payment|token)/i, 'منطق إعادة المحاولة قرب طلب حساس.', 'قد يكرر عملية دفع أو يرسل رمزًا أكثر من مرة.', 'استخدم idempotency key وقيّد retries وسجّل النتيجة بأمان.', 'مسار التهديد: إعادة إرسال → تكرار عملية → رسوم أو تغيير حالة.'),
  rule('webview-file-url', 'السماح بقراءة ملفات URL', 'critical', 'WebView', /setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|allowFileAccessFromFileURLs\s*[:=]\s*true/i, 'WebView يسمح للملفات بقراءة ملفات أخرى.', 'قد يحول محتوى محلي أو خارجي إلى قراءة أسرار التطبيق.', 'عطّل الخاصية واستخدم موارد مضمنة ومسارات محددة.', 'مسار التهديد: ملف HTML → قراءة ملفات محلية → تسريب أسرار.'),
  rule('webview-universal-file-url', 'السماح بوصول شامل من ملفات URL', 'critical', 'WebView', /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|allowUniversalAccessFromFileURLs\s*[:=]\s*true/i, 'الملفات تستطيع طلب موارد من origins أخرى.', 'يوسع أثر XSS أو ملف HTML غير موثوق إلى الشبكة والملفات.', 'عطّلها دائمًا في release واعزل المحتوى غير الموثوق.', 'مسار التهديد: ملف محلي → طلب cross-origin → كشف بيانات.'),
  rule('webview-debugging', 'تصحيح WebView مفعّل', 'high', 'WebView', /setWebContentsDebuggingEnabled\s*\(\s*true\s*\)|webContentsDebuggingEnabled\s*[:=]\s*true/i, 'أدوات تصحيح WebView مفعلة.', 'قد تسمح بفحص DOM والرسائل في نسخة الإنتاج.', 'اجعلها مشروطة بـ __DEV__ وتحقق من release binary.', 'مسار التهديد: WebView debug → فحص جلسة/bridge → استخراج بيانات.'),
  rule('webview-mixed-content', 'Mixed Content في WebView', 'high', 'WebView', /mixedContentMode\s*[:=]\s*["'](?:always|compatibility)["']/i, 'السماح بمحتوى HTTP داخل صفحة HTTPS.', 'قد يعيد إدخال محتوى قابل للاعتراض داخل سياق موثوق.', 'استخدم neverAllow في release وأصلح الموارد غير المشفرة.', 'مسار التهديد: مورد HTTP → تعديل محتوى → تنفيذ أو تصيد.'),
  rule('webview-dom-storage', 'DOM Storage في WebView', 'medium', 'WebView', /domStorageEnabled\s*[:=]\s*true/i, 'تخزين DOM مفعل في محتوى ويب.', 'قد يحتفظ برموز أو بيانات بعد مغادرة الصفحة.', 'لا تضع أسرارًا في localStorage ونظّف بيانات الجلسة عند الإغلاق.', 'مسار التهديد: storage دائم → استخراج محلي → إعادة استخدام جلسة.'),
  rule('webview-untrusted-url', 'تحميل رابط WebView ديناميكي', 'high', 'WebView', /(?:WebView|webview)[\s\S]{0,160}(?:loadUrl|source\s*[:=])[\s\S]{0,160}(?:https?:\/\/|url)/i, 'يتم تحميل مصدر يمكن أن يكون ديناميكيًا.', 'قد يصل محتوى غير موثوق إلى bridge أو session cookies.', 'استخدم allowlist كاملة للنطاقات وامنع التنقلات غير المتوقعة.', 'مسار التهديد: رابط غير موثوق → صفحة محقونة → تسريب أو bridge abuse.'),
  rule('input-eval', 'تقييم نص ككود', 'critical', 'الإدخال والتنفيذ', /(?:\beval\s*\(|new\s+Function\s*\(|javascript\s*:)/i, 'تحويل نص أو رابط إلى كود قابل للتنفيذ.', 'قد يحول مدخلًا غير موثوق إلى تنفيذ داخل سياق التطبيق.', 'أزل التقييم الديناميكي واستخدم parser وقائمة أوامر صريحة.', 'مسار التهديد: نص خارجي → تقييم كود → تنفيذ غير مقصود.'),
  rule('input-command-exec', 'تنفيذ أمر نظام', 'critical', 'الإدخال والتنفيذ', /(?:Runtime\.getRuntime\s*\(\s*\)\.exec|ProcessBuilder\s*\(|child_process|execFile\s*\()/i, 'استدعاء تنفيذ أوامر نظام.', 'قد يسمح بتحويل مدخل غير موثوق إلى أمر على الجهاز أو بيئة CI.', 'لا تبنِ أوامر من مدخل خارجي واستخدم APIs typed بدل shell.', 'مسار التهديد: مدخل خارجي → أمر نظام → قراءة أو تغيير بيئة.'),
  rule('input-intent-extra', 'مدخل Intent غير موثوق', 'medium', 'الإدخال والتنفيذ', /(?:getIntent\s*\(\s*\)|getStringExtra|getParcelableExtra|getSerializableExtra)/i, 'قراءة قيم واردة من Intent.', 'قد تمرر تطبيقات أخرى قيمًا غير متوقعة إلى وظائف حساسة.', 'تحقق من النوع والحجم والمصدر ولا تثق بـ extras.', 'مسار التهديد: تطبيق آخر → extra مزور → تنفيذ وظيفة حساسة.'),
  rule('input-uri-authority', 'URI authority غير متحقق', 'high', 'Deep Links', /(?:getData\s*\(\s*\)|uri\.host|uri\.authority|URL\()/i, 'تحليل URI وارد من الخارج.', 'قد يسمح بتجاوز النطاق أو تغيير callback إلى جهة أخرى.', 'قارن scheme وhost وpath بقائمة صريحة قبل أي إجراء.', 'مسار التهديد: URI مزور → callback/شاشة حساسة → تصيد أو ربط خاطئ.'),
  rule('input-json-parse', 'تحليل JSON خارجي دون مخطط', 'medium', 'الإدخال والتنفيذ', /JSON\.parse\s*\(|JSONObject\s*\(/i, 'تحليل بيانات دون ظهور مخطط تحقق.', 'قد يؤدي إلى أنواع أو قيم غير متوقعة downstream.', 'استخدم schema validation وحدود حجم ورفض الحقول غير المعروفة.', 'مسار التهديد: JSON معدل → حالة غير متوقعة → تجاوز منطق.'),
  rule('input-regex-dos', 'Regex قد يتأثر بمدخل طويل', 'medium', 'الإدخال والتنفيذ', /(?:new\s+RegExp|Pattern\.compile|\/\(.+\+\).+\/)/i, 'تجميع تعبير منتظم أو نمط تكراري حساس.', 'قد يستهلك CPU عند مدخل مصمم بعناية.', 'استخدم regex بسيطًا وحدد الطول والمهلة واختبر worst-case.', 'مسار التهديد: نص طويل → backtracking → تجميد واجهة أو خدمة.'),
  rule('archive-zip-slip', 'استخراج مسار ZIP غير مقيد', 'critical', 'الملفات والأرشيف', /(?:ZipEntry|unzip|extract|decompress)[\s\S]{0,120}(?:getName|entry\.name|writeFile)/i, 'استخراج أسماء ملفات من أرشيف.', 'قد يكتب ملفًا خارج مجلد الهدف إذا احتوى الاسم على traversal.', 'طبّع المسار وتحقق أنه داخل مجلد الوجهة وارفض absolute paths.', 'مسار التهديد: أرشيف معدل → مسار خارج root → استبدال ملف.'),
  rule('archive-untrusted-size', 'ضغط/أرشيف دون حدود حجم', 'medium', 'الملفات والأرشيف', /(?:ZipFile|JSZip|unzip|inflate|decompress)/i, 'معالجة أرشيف دون ظهور حد واضح للحجم.', 'قد يستنزف الذاكرة أو التخزين عبر قنبلة ضغط.', 'ضع حدًا لعدد الملفات والحجم بعد الفك والعمق وزمن المعالجة.', 'مسار التهديد: أرشيف صغير → توسع ضخم → OOM أو توقف الخدمة.'),
  rule('file-temp-unsafe', 'ملف مؤقت يحتاج تنظيفًا', 'medium', 'الملفات والأرشيف', /(?:createTempFile|tmpdir|cacheDir|File\.createTempFile)/i, 'إنشاء ملف مؤقت أو استخدام cache.', 'قد تبقى نسخة حساسة في التخزين بعد انتهاء العملية.', 'نظّف الملف في finally واستخدم صلاحيات التطبيق وحدود retention.', 'مسار التهديد: ملف مؤقت → استخراج محلي → كشف بيانات.'),
  rule('file-external-storage', 'كتابة إلى تخزين مشترك', 'high', 'تخزين', /(?:getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY_DOWNLOADS|\/sdcard)/i, 'كتابة أو قراءة من موقع مشترك.', 'تطبيقات أخرى أو نسخ احتياطية قد تصل إلى البيانات.', 'استخدم internal storage للبيانات الحساسة وشارك عبر URI مؤقت.', 'مسار التهديد: تخزين مشترك → تطبيق آخر → قراءة أو استبدال.'),
  rule('file-world-readable', 'ملف قابل للقراءة عالميًا', 'critical', 'تخزين', /MODE_WORLD_READABLE|openFileOutput\s*\([^)]*,\s*1\s*\)/i, 'إعداد صلاحية ملف قد يسمح بالقراءة خارج التطبيق.', 'يكشف أسرارًا مباشرة لتطبيقات أخرى أو أدوات الجهاز.', 'استخدم MODE_PRIVATE وافحص صلاحيات الملفات بعد البناء.', 'مسار التهديد: ملف عام → قراءة خارجية → سرقة بيانات.'),
  rule('file-world-writable', 'ملف قابل للكتابة عالميًا', 'critical', 'تخزين', /MODE_WORLD_WRITEABLE|openFileOutput\s*\([^)]*,\s*2\s*\)/i, 'ملف يمكن لجهة خارجية تعديله.', 'قد يغير إعدادًا أو كودًا أو حالة ثقة داخل التطبيق.', 'استخدم MODE_PRIVATE وتحقق من سلامة الملفات قبل القراءة.', 'مسار التهديد: ملف قابل للكتابة → تغيير حالة → تجاوز منطق.'),
  rule('storage-db-backup', 'قاعدة بيانات محلية تحتاج حماية', 'high', 'تخزين', /(?:SQLiteDatabase|Room\.databaseBuilder|openOrCreateDatabase)/i, 'قاعدة بيانات محلية موجودة.', 'قد تحتوي على جلسات أو PII وتدخل في backup أو debug.', 'شفّر الحقول الحساسة، امنع backup المناسب، ونظّف السجلات.', 'مسار التهديد: قاعدة محلية → نسخة احتياطية/جهاز معدل → كشف بيانات.'),
  rule('storage-key-material', 'مادة مفتاح في تخزين عام', 'critical', 'التشفير', /(?:encryptionKey|secretKey|privateKey)[\s\S]{0,80}(?:SharedPreferences|AsyncStorage|localStorage|NSUserDefaults)/i, 'تخزين مادة مفتاح قرب مخزن عام.', 'يسقط التشفير إذا أمكن استخراج المفتاح مع ciphertext.', 'ضع المفتاح في Keystore/Keychain أو استخدم envelope encryption.', 'مسار التهديد: مخزن عام → استخراج المفتاح → فك بيانات التطبيق.'),
  rule('crypto-static-salt', 'Salt ثابت', 'medium', 'التشفير', /(?:salt|passwordSalt)\s*=\s*["'][^"']{4,}["']/i, 'قيمة salt ثابتة داخل الحزمة.', 'يسهّل المقارنة والتحليل عند تخزين كلمات مرور أو مشتقات مفاتيح.', 'استخدم salt عشوائيًا وفريدًا لكل سجل مع KDF مناسب.', 'مسار التهديد: salt ثابت → جداول مسبقة/مقارنة → كشف أسرار.'),
  rule('crypto-weak-kdf', 'اشتقاق مفتاح ضعيف أو قليل التكرار', 'high', 'التشفير', /(?:PBKDF2WithHmacSHA1|PBEWithMD5AndDES|iterations\s*[:=]\s*[1-9]\d{0,2})/i, 'استخدام KDF قديم أو عدد تكرارات منخفض.', 'يسهّل تخمين كلمات المرور عند تسريب hash.', 'استخدم KDF حديثًا بإعدادات موثقة وsalt عشوائي وقياس أداء.', 'مسار التهديد: hash ضعيف → تخمين سريع → فك بيانات.'),
  rule('crypto-key-export', 'تصدير مفتاح من Keystore', 'high', 'التشفير', /(?:KeyStore|SecureKey|Keychain)[\s\S]{0,100}(?:getEncoded|export|toBase64)/i, 'محاولة استخراج مفتاح من مخزن آمن.', 'قد يفقد Keystore فائدته إذا تحول المفتاح إلى bytes قابلة للنسخ.', 'استخدم المفتاح داخل primitive فقط وامنع إخراجه للذاكرة العامة.', 'مسار التهديد: مفتاح مصدّر → نسخة قابلة للاستخراج → فك أو توقيع.'),
  rule('crypto-no-authentication', 'تشفير دون مصادقة', 'high', 'التشفير', /(?:AES\/CBC|AES\/CTR|Cipher\.getInstance\s*\(\s*["']AES\/(?:CBC|CTR))/i, 'وضع تشفير لا يضمن سلامة النص وحده.', 'قد يقبل التطبيق نصًا معدلًا دون اكتشاف التلاعب.', 'استخدم AEAD مثل AES-GCM وتحقق من tag قبل فك المحتوى.', 'مسار التهديد: ciphertext معدل → فك مقبول → تغيير بيانات.'),
  rule('auth-password-client', 'كلمة مرور تُعالج على العميل', 'high', 'المصادقة', /(?:password|passwd|passcode)[\s\S]{0,100}(?:fetch|axios|request|AsyncStorage|localStorage)/i, 'منطق كلمة مرور قرب النقل أو التخزين.', 'قد تظهر في سجلات أو تخزين أو طلبات غير محمية.', 'استخدم TLS، لا تسجلها، ولا تحفظها؛ دع الخادم يتحقق ويصدر جلسة.', 'مسار التهديد: كلمة مرور → سجل/تخزين → انتحال حساب.'),
  rule('auth-otp-logging', 'رمز OTP قرب السجلات', 'high', 'المصادقة', /(?:otp|oneTimeCode|verificationCode|smsCode)[\s\S]{0,80}(?:console\.log|Log\.|print|logger)/i, 'رمز تحقق قريب من نداء تسجيل.', 'قد يقرأه مستخدم أو نظام تجميع سجلات.', 'احذف تسجيل الرموز وطبّق redaction واستخدم مدة صلاحية قصيرة.', 'مسار التهديد: OTP في سجل → قراءة → إكمال تسجيل الدخول.'),
  rule('auth-session-timeout', 'جلسة دون مؤشرات انتهاء', 'medium', 'الجلسات', /(?:session|accessToken|refreshToken)[\s\S]{0,120}(?!exp|expires|ttl|timeout)/i, 'جلسة أو رمز دون ظهور سياسة انتهاء قريبة.', 'الجلسات الطويلة تزيد أثر التسريب وإعادة الاستخدام.', 'طبّق expiry وrotation وإبطالًا server-side عند الخروج أو الاشتباه.', 'مسار التهديد: رمز طويل العمر → تسريب → وصول ممتد.'),
  rule('auth-refresh-storage', 'Refresh token في تخزين العميل', 'high', 'الجلسات', /refreshToken[\s\S]{0,100}(?:AsyncStorage|localStorage|SharedPreferences|NSUserDefaults)/i, 'تخزين refresh token في مخزن عام.', 'يمكن أن يطيل عمر جلسة مسروقة.', 'استخدم Keychain/Keystore مع rotation واكتشاف replay.', 'مسار التهديد: refresh token → استخراج → تجديد جلسة بلا حضور المستخدم.'),
  rule('auth-logout-local', 'تسجيل خروج محلي فقط', 'high', 'الجلسات', /(?:logout|signOut)[\s\S]{0,160}(?:removeItem|clear|setItem|AsyncStorage)/i, 'تدفق الخروج يبدو محليًا فقط.', 'قد تبقى الجلسة صالحة على الخادم أو جهاز آخر.', 'أبطل refresh token على الخادم ثم نظّف التخزين المحلي.', 'مسار التهديد: خروج محلي → رمز خادم صالح → إعادة استخدام الجلسة.'),
  rule('auth-account-enumeration', 'رسائل مصادقة تكشف وجود الحساب', 'medium', 'المصادقة', /(?:user\s+not\s+found|email\s+not\s+registered|account\s+does\s+not\s+exist)/i, 'رسالة مختلفة للحساب غير الموجود.', 'قد تسمح بتعداد المستخدمين عبر واجهة الدخول.', 'وحّد رسائل الخطأ وزمن الاستجابة وسجّل التفاصيل داخليًا فقط.', 'مسار التهديد: رسائل مختلفة → تعداد حسابات → تصيد مستهدف.'),
  rule('auth-magic-link-url', 'رابط سحري داخل query', 'high', 'المصادقة', /(?:magicLink|loginLink|passwordReset)[\s\S]{0,100}(?:\?|query|url|Linking)/i, 'تدفق رابط دخول أو إعادة ضبط.', 'قد يتسرب الرمز عبر السجل أو الإحالة أو تطبيق آخر.', 'استخدم روابط قصيرة العمر مع state وPKCE وامنع الأسرار من analytics.', 'مسار التهديد: رابط دخول → تسريب callback → انتحال حساب.'),
  rule('auth-mfa-optional', 'MFA اختياري قرب وظيفة حساسة', 'medium', 'المصادقة', /(?:mfa|twoFactor|2fa)[\s\S]{0,120}(?:optional|skip|disabled|false)/i, 'وجود مسار يسمح بتجاوز عامل إضافي.', 'قد يترك الحسابات الحساسة مع كلمة مرور فقط.', 'اجعل MFA إلزاميًا للعمليات عالية الأثر وطبّق step-up auth.', 'مسار التهديد: تجاوز MFA → دخول بحساب مسروق → إجراء حساس.'),
  rule('auth-biometric-fallback', 'Fallback حيوي غير محمي', 'high', 'المصادقة', /(?:biometric|BiometricPrompt|FaceID|TouchID)[\s\S]{0,140}(?:fallback|password|success|true)/i, 'تدفق biometric يتضمن fallback يحتاج مراجعة.', 'قد يعتبر التطبيق fallback إثباتًا كافيًا لعملية حساسة.', 'اربط كل نجاح بـ key operation وstep-up server-side للعمليات الحرجة.', 'مسار التهديد: fallback ضعيف → تأكيد زائف → كشف أو تحويل.'),
  rule('auth-state-redirect', 'حالة OAuth دون تحقق state', 'high', 'المصادقة', /(?:oauth|authorize|callback)[\s\S]{0,180}(?!state|nonce)/i, 'تدفق callback لا يظهر فيه تحقق state أو nonce.', 'قد يفتح ربط حساب أو جلسة cross-site request.', 'ولّد state عشوائيًا واربطه بالجلسة وتحقق منه مرة واحدة.', 'مسار التهديد: callback مزور → ربط جلسة خاطئة → account takeover.'),
  rule('auth-pkce-missing', 'OAuth دون PKCE ظاهر', 'high', 'المصادقة', /(?:authorization_code|redirect_uri|client_id)[\s\S]{0,160}(?!code_challenge|code_verifier|PKCE)/i, 'مؤشرات OAuth دون ظهور حماية PKCE.', 'قد يسهل اعتراض code في تطبيق عام.', 'استخدم Authorization Code + PKCE ولا تضع client secret في التطبيق.', 'مسار التهديد: اعتراض code → استبدال رمز → دخول غير مصرح.'),
  rule('privacy-contacts', 'قراءة جهات الاتصال', 'high', 'الخصوصية', /READ_CONTACTS|WRITE_CONTACTS|ContactsContract|Contacts\.getAll/i, 'الوصول إلى جهات اتصال المستخدم.', 'يكشف شبكة اجتماعية وبيانات أشخاص آخرين.', 'اطلبها عند الحاجة فقط ووضح الغرض وامنع الرفع غير الضروري.', 'مسار التهديد: جهات اتصال → رفع زائد → كشف خصوصية أطراف أخرى.'),
  rule('privacy-microphone', 'تسجيل صوت', 'high', 'الخصوصية', /RECORD_AUDIO|AudioRecord|MediaRecorder|AVAudioRecorder/i, 'الوصول إلى الميكروفون أو التسجيل.', 'قد يسبب أثرًا عاليًا إذا بدأ دون سياق مرئي للمستخدم.', 'اطلب الإذن في السياق، أظهر حالة التسجيل، وأوقفه عند الخلفية.', 'مسار التهديد: ميكروفون → تسجيل غير متوقع → كشف محادثات.'),
  rule('privacy-bluetooth', 'أجهزة Bluetooth قريبة', 'medium', 'الخصوصية', /BLUETOOTH_SCAN|BLUETOOTH_CONNECT|BluetoothAdapter|Nearby/i, 'الوصول إلى أجهزة قريبة.', 'قد يكشف وجود أجهزة أو موقعًا تقريبيًا للمستخدم.', 'قلل المسح، استخدم neverForLocation عند ملاءمته، ووضح الاحتفاظ.', 'مسار التهديد: مسح قريب → بصمة بيئة → استنتاج موقع/هوية.'),
  rule('privacy-sms', 'قراءة أو إرسال SMS', 'high', 'الخصوصية', /READ_SMS|RECEIVE_SMS|SEND_SMS|SmsManager|TelephonyManager/i, 'الوصول إلى الرسائل أو الاتصالات.', 'قد يكشف رموز MFA أو يسمح برسائل مدفوعة.', 'لا تطلبها إلا لسبب أساسي، واستخدم APIs الرسمية الأقل صلاحية.', 'مسار التهديد: SMS/OTP → قراءة أو إرسال → انتحال أو تكلفة.'),
  rule('privacy-phone-identifiers', 'معرّفات هاتف دائمة', 'high', 'الخصوصية', /(?:IMEI|TelephonyManager\.getDeviceId|SERIAL|Build\.getSerial|MacAddress)/i, 'جمع معرف جهاز دائم أو حساس.', 'يصعّب إعادة الضبط ويربط النشاط بالمستخدم.', 'استخدم معرفًا عشوائيًا قابلًا لإعادة الضبط مع إفصاح وقيود وصول.', 'مسار التهديد: معرف دائم → ربط خدمات → تتبع طويل الأمد.'),
  rule('privacy-email-collection', 'جمع بريد أو هاتف دون سياق ظاهر', 'medium', 'الخصوصية', /(?:email|phoneNumber|mobileNumber)[\s\S]{0,100}(?:analytics|telemetry|track|log)/i, 'بيانات اتصال قرب telemetry أو logging.', 'قد تُرسل PII إلى مراقبة أو تحليلات دون تقليل.', 'طبّق data minimization وhash/ظلل القيم في telemetry.', 'مسار التهديد: PII في telemetry → وصول واسع → كشف هوية.'),
  rule('privacy-notification-content', 'محتوى حساس في الإشعارات', 'medium', 'الخصوصية', /(?:Notification|notify|push)[\s\S]{0,100}(?:token|password|otp|message|email)/i, 'إدخال بيانات قد تكون حساسة في إشعار.', 'قد تظهر على شاشة القفل أو جهاز مرتبط.', 'استخدم عنوانًا عامًا ومحتوى خاصًا بعد فتح التطبيق.', 'مسار التهديد: شاشة قفل → قراءة إشعار → كشف بيانات.'),
  rule('privacy-analytics-pii', 'PII في تحليلات أو breadcrumbs', 'high', 'الخصوصية', /(?:analytics|track|breadcrumb|event)[\s\S]{0,120}(?:email|phone|name|address|token)/i, 'حقول شخصية قرب إرسال تحليلات.', 'قد تتسرب PII إلى مزود خارجي أو سجلات طويلة الأجل.', 'احذف الحقول أو ظللها وطبّق allowlist للأحداث.', 'مسار التهديد: حدث تحليلي → مزود خارجي → كشف أو ربط سلوك.'),
  rule('privacy-background-location', 'موقع في الخلفية', 'high', 'الخصوصية', /ACCESS_BACKGROUND_LOCATION|startLocationUpdatesAsync|backgroundLocation/i, 'جمع الموقع في الخلفية.', 'أثر الخصوصية أعلى من الموقع أثناء الاستخدام.', 'استخدمه فقط لميزة أساسية مع مؤشر واضح وسياسة احتفاظ قصيرة.', 'مسار التهديد: جمع مستمر → سجل تحركات → كشف موقع حساس.'),
  rule('supplychain-dynamic-gradle', 'إصدار Gradle ديناميكي', 'high', 'سلسلة التوريد', /(?:implementation|api)\s+["'][^"']+:[^"']+:[+*xX][^"']*["']/i, 'اعتماد بلا نسخة ثابتة.', 'قد يدخل إصدار جديد غير مُراجع في بناء لاحق.', 'ثبّت الإصدارات واستخدم lockfile ومراجعة تغييرات CI.', 'مسار التهديد: تحديث تلقائي → dependency خبيث/مكسور → إصدار متأثر.'),
  rule('supplychain-jcenter', 'مستودع JCenter قديم', 'medium', 'سلسلة التوريد', /jcenter\s*\(\s*\)|jcenter\(\)/i, 'استخدام مستودع متقاعد أو أقل وضوحًا.', 'يزيد خطر اعتماد غير مُصان أو مصدر غير متوقع.', 'انقل الاعتمادات إلى مستودعات موثوقة وثبّت checksum عند الإمكان.', 'مسار التهديد: مستودع قديم → package غير موثوق → إدخال كود.'),
  rule('supplychain-maven-local', 'Maven Local في إعداد البناء', 'high', 'سلسلة التوريد', /mavenLocal\s*\(\s*\)/i, 'البناء يقرأ من مستودع محلي.', 'قد يختلف البناء بين الأجهزة أو يحقن artifact محليًا.', 'امنعه في release واستخدم مستودعًا معروفًا مع تحقق توقيع.', 'مسار التهديد: artifact محلي → اختلاف build → حزمة غير مراجعة.'),
  rule('supplychain-gradle-script', 'تحميل سكربت Gradle عن بعد', 'critical', 'سلسلة التوريد', /apply\s+from\s*:\s*["']https?:\/\/|apply\(from\s*=\s*["']https?:\/\//i, 'تنفيذ سكربت بناء من رابط خارجي.', 'المصدر الخارجي قد يغير التطبيق أو سلسلة البناء.', 'نزّل السكربت وراجعه وثبّت checksum بدل التنفيذ عن بعد.', 'مسار التهديد: رابط بناء → كود CI → artifact خبيث.'),
  rule('supplychain-npm-install-script', 'سكريبت تثبيت اعتماد', 'medium', 'سلسلة التوريد', /(?:preinstall|postinstall|prepare)\s*["']?\s*:/i, 'وجود lifecycle script في metadata.', 'قد ينفذ كودًا أثناء تثبيت الاعتمادات أو البناء.', 'راجع scripts وأوقف غير الضروري داخل CI sandbox.', 'مسار التهديد: install script → تنفيذ build-time → تسريب أو تعديل artifact.'),
  rule('supplychain-debug-build', 'إعداد debug في release', 'high', 'سلسلة التوريد', /(?:buildType|variant|buildConfig)[\s\S]{0,80}(?:debug|development)/i, 'مؤشر على variant تطوير.', 'قد تُشحن logging أو endpoints أو صلاحيات أوسع.', 'افحص artifact النهائي ووقّعه من pipeline منفصل.', 'مسار التهديد: variant debug → أدوات تحليل → كشف أسرار.'),
  rule('supplychain-minify-disabled', 'تصغير الكود معطل', 'medium', 'سلسلة التوريد', /minifyEnabled\s+(?:false|0)|minify\s*[:=]\s*false/i, 'التصغير أو obfuscation غير مفعّل.', 'يسهّل تحليل منطق العميل واستخراج أسماء حساسة.', 'فعّل R8/ProGuard مع keep rules دقيقة واختبر release.', 'مسار التهديد: كود واضح → تحليل أسرع → استهداف منطق حساس.'),
  rule('supplychain-shrink-disabled', 'تقليص الموارد معطل', 'low', 'سلسلة التوريد', /shrinkResources\s+(?:false|0)/i, 'الموارد غير المستخدمة تبقى في الحزمة.', 'قد تكشف بيئات أو endpoints أو شاشات قديمة.', 'فعّل shrinkResources بعد اختبار البناء واحذف artifacts القديمة.', 'مسار التهديد: مورد متروك → كشف معلومات → استكشاف مسار قديم.'),
  rule('supplychain-mapping-public', 'خريطة mapping ضمن الإصدار', 'high', 'سلسلة التوريد', /(?:mapping|proguard)\.(?:txt|map)|uploadMapping/i, 'ملف mapping أو رفعه في مسار قد يظهر للعميل.', 'يكشف أسماء الكود ويزيد دقة التحليل العكسي.', 'ارفع الخرائط إلى مخزن خاص بالمراقبة فقط.', 'مسار التهديد: mapping → أسماء داخلية → استهداف أسرع.'),
  rule('supplychain-dev-server', 'عنوان Metro أو dev server', 'high', 'سلسلة التوريد', /(?:metro|webpack|devServer|packager)[\s\S]{0,100}(?:localhost|http:\/\/|ws:\/\/)/i, 'مؤشر على عنوان تطوير مضمّن.', 'قد تفشل النسخة أو تتصل ببيئة غير موثوقة.', 'تأكد من عدم وجود dev server في bundle النهائي.', 'مسار التهديد: bundle تطوير → اتصال خارجي → تحميل كود/كشف بيانات.'),
  rule('supplychain-ota-update', 'تحديث OTA يحتاج تحقق سلامة', 'high', 'سلسلة التوريد', /(?:expo-updates|CodePush|OTA|Updates\.reloadAsync|updateUrl)/i, 'التطبيق يدعم تحديثًا خارج المتجر.', 'التحديث يصبح قناة كود إضافية يجب حمايتها.', 'استخدم توقيع updates وقناة موثوقة وrollback ومراجعة provenance.', 'مسار التهديد: قناة OTA → update معدل → تنفيذ داخل التطبيق.'),
  rule('supplychain-unpinned-update', 'مصدر تحديث غير مثبت', 'critical', 'سلسلة التوريد', /(?:updateUrl|manifestUrl|bundleUrl)\s*[:=]\s*["']https?:\/\/[^"']+["']/i, 'رابط تحديث ثابت دون مؤشر تحقق توقيع.', 'اختراق المصدر قد يوزع كودًا لكل المستخدمين.', 'تحقق من توقيع manifest وTLS ولا تعتمد على إخفاء الرابط.', 'مسار التهديد: مصدر تحديث → bundle معدل → انتشار واسع.'),
  rule('supplychain-native-symbols', 'رموز Native قابلة للتحليل', 'low', 'سلسلة التوريد', /(?:jniLibs|symbols|ndkVersion|debugSymbols)/i, 'إعداد أو artifact رموز Native.', 'قد يكشف دوال داخلية ويصعب حماية الذاكرة.', 'افصل symbols عن الإصدار واستخدم hardening وstrip للـ release.', 'مسار التهديد: رموز Native → فهم السطح → استهداف memory bugs.'),
  rule('platform-accessibility-service', 'خدمة وصول ذات صلاحيات واسعة', 'critical', 'الخصوصية والصلاحيات', /BIND_ACCESSIBILITY_SERVICE|onAccessibilityEvent|AccessibilityNodeInfo/i, 'استخدام Accessibility APIs أو خدمة وصول.', 'قد تقرأ واجهات أخرى وتنفذ نقرات أو تلتقط أسرارًا.', 'لا تستخدمها إلا لحالة وصول أساسية وبأقل أحداث وصلاحيات.', 'مسار التهديد: حدث شاشة → قراءة OTP/حساب → انتحال مستخدم.'),
  rule('platform-device-admin', 'Device Admin أو إدارة جهاز', 'high', 'الخصوصية والصلاحيات', /DeviceAdminReceiver|BIND_DEVICE_ADMIN|DevicePolicyManager/i, 'طلب صلاحيات إدارة الجهاز.', 'قد يقفل أو يمسح أو يغير سياسات الجهاز.', 'استخدم MDM رسميًا عند الحاجة ووثّق كل إجراء واطلب موافقة واضحة.', 'مسار التهديد: صلاحية إدارة → إجراء قسري → فقدان بيانات أو سيطرة.'),
  rule('platform-vpn-service', 'VPN Service داخل التطبيق', 'high', 'الشبكة والصلاحيات', /VpnService|BIND_VPN_SERVICE/i, 'التطبيق يمكنه اعتراض مرور الجهاز.', 'أي خطأ قد يكشف أو يعدل بيانات تطبيقات أخرى.', 'وضح نطاق المرور، لا تسجل المحتوى، واحمِ مفاتيح النفق.', 'مسار التهديد: VPN واسع → اعتراض مرور → كشف حسابات أو PII.'),
  rule('platform-notification-listener', 'قراءة إشعارات الجهاز', 'high', 'الخصوصية والصلاحيات', /NotificationListenerService|BIND_NOTIFICATION_LISTENER_SERVICE/i, 'خدمة تقرأ إشعارات تطبيقات أخرى.', 'قد تكشف OTP ورسائل ومحتوى خاص.', 'اجعل الاستخدام اختياريًا ومحدودًا ولا تحفظ المحتوى.', 'مسار التهديد: إشعار OTP → خدمة القراءة → انتحال حساب.'),
  rule('platform-foreground-service', 'Foreground Service دائم', 'medium', 'الخصوصية والصلاحيات', /FOREGROUND_SERVICE|startForegroundService|startForeground\s*\(/i, 'خدمة تعمل في المقدمة أو الخلفية.', 'قد تجمع موقعًا أو صوتًا أو بيانات مدة أطول من المتوقع.', 'أظهر إشعارًا واضحًا وأوقف الخدمة عند انتهاء الغرض.', 'مسار التهديد: خدمة دائمة → جمع زائد → كشف خصوصية.'),
  rule('platform-alarm-receiver', 'منبه أو Receiver دوري', 'low', 'سطح Android', /AlarmManager|setRepeating|setExactAndAllowWhileIdle/i, 'تشغيل دوري في الخلفية.', 'قد ينفذ وظيفة حساسة بعد انتهاء الجلسة أو دون سياق.', 'تحقق من session state ولا تضع أسرارًا في extras.', 'مسار التهديد: alarm متأخر → حالة قديمة → إرسال أو تغيير غير مقصود.'),
  rule('platform-accessibility-overlay', 'Overlay قرب بيانات دخول', 'critical', 'الخصوصية والصلاحيات', /TYPE_APPLICATION_OVERLAY[\s\S]{0,160}(?:login|password|otp|auth)/i, 'طبقة فوق التطبيقات قرب مدخلات مصادقة.', 'قد تتحول إلى واجهة تصيد أو اعتراض لمس.', 'أزل overlay غير الضروري وامنعه على شاشات المصادقة.', 'مسار التهديد: overlay → واجهة مزورة → سرقة اعتماد.'),
  rule('quality-error-swallow', 'ابتلاع أخطاء أمنيّة', 'medium', 'المرونة والموثوقية', /catch\s*(?:\([^)]*\))?\s*\{\s*(?:return|continue|break|\/\/|\/\*)/i, 'كتلة catch لا يظهر فيها تسجيل آمن أو معالجة واضحة.', 'قد يخفي فشل تحقق أو شهادة أو مصادقة ويكمل التنفيذ.', 'افصل الأخطاء القابلة للتعافي عن فشل الأمان وارفض افتراضيًا.', 'مسار التهديد: فشل تحقق → catch صامت → قرار آمن خاطئ.'),
  rule('quality-fail-open', 'فشل آمن إلى true أو سماح', 'critical', 'المرونة والموثوقية', /catch[\s\S]{0,120}(?:return\s+true|allow\s*[:=]\s*true|authorized\s*[:=]\s*true)/i, 'عند الخطأ يظهر مسار سماح.', 'انقطاع الشبكة أو خطأ parsing قد يتحول إلى تجاوز حماية.', 'استخدم fail closed وسجّل السبب دون كشف بيانات.', 'مسار التهديد: خطأ عابر → سماح افتراضي → تجاوز صلاحية.'),
  rule('quality-hardcoded-role', 'دور أو صلاحية ثابتة', 'high', 'التحكم بالوصول', /(?:role|permission|isAdmin|isModerator)\s*[:=]\s*["'](?:admin|owner|moderator|staff)["']|(?:isAdmin|isStaff)\s*[:=]\s*true/i, 'قرار دور أو صلاحية داخل العميل.', 'يمكن تعديل القرار محليًا إذا اعتمد عليه الخادم.', 'اجعل الخادم مصدر الحقيقة ووقّع claims قصيرة العمر.', 'مسار التهديد: تعديل role محلي → تفعيل وظيفة إدارية → تغيير بيانات.'),
  rule('quality-object-merge', 'دمج مدخل مع إعدادات حساسة', 'high', 'التحكم بالوصول', /(?:Object\.assign|\.{3})[\s\S]{0,80}(?:config|options|permissions|admin|security)/i, 'دمج بيانات واردة مع إعدادات أو خيارات.', 'قد يغيّر مدخل خارجي flags أو callbacks حساسة.', 'استخدم allowlist للحقول وانسخ القيم المسموحة فقط.', 'مسار التهديد: object merge → تغيير flag → تجاوز سلوك أمني.'),
  rule('quality-http-status-trust', 'الثقة في HTTP status فقط', 'medium', 'المرونة والموثوقية', /response\.status\s*===\s*200[\s\S]{0,100}(?:authorized|premium|success|verified)/i, 'ربط حالة نجاح النقل بقرار أمني أو entitlement.', 'قد يقبل payload غير متحقق أو response من وسيط.', 'تحقق من schema والتوقيع والهوية، لا status وحده.', 'مسار التهديد: response 200 مزور → قرار ثقة → وصول غير مصرح.'),
  rule('quality-unsigned-config', 'إعدادات عن بعد دون توقيع', 'high', 'المرونة والموثوقية', /(?:remoteConfig|featureFlags|fetchConfig|dynamicConfig)[\s\S]{0,140}(?!signature|verify|hmac)/i, 'تحميل flags أو إعدادات دون ظهور تحقق سلامة.', 'قد يفعّل وظيفة حساسة عبر استجابة معدلة.', 'وقّع الإعدادات أو قيد القيم بالخادم وتحقق من schema وversion.', 'مسار التهديد: config معدل → تفعيل مسار حساس → كشف أو خسارة.'),
  rule('quality-debug-menu', 'قائمة Debug داخل الإصدار', 'medium', 'سلسلة التوريد', /(?:debugMenu|devMenu|developerOptions|showInspector)\s*[:=]\s*(?:true|1)/i, 'وظائف تصحيح متاحة بصيغة ثابتة.', 'قد تكشف endpoints أو تغيّر حالة التطبيق.', 'أزلها من release عبر dead-code elimination واختبار snapshot.', 'مسار التهديد: debug menu → تغيير إعداد → تسريب أو تجاوز.'),
  rule('quality-test-credentials', 'بيانات اختبار داخل الحزمة', 'high', 'سلسلة التوريد', /(?:test(?:User|Email|Password)|demo(?:Token|Account)|qaPassword|fixture)/i, 'أسماء بيانات اختبار أو حساب تجريبي.', 'قد تُستخدم كنقطة دخول أو تكشف بيئة داخلية.', 'احذف fixtures من release ودوّر أي اعتماد ظهر في build.', 'مسار التهديد: اعتماد اختبار → دخول → انتقال إلى بيانات حقيقية.'),
  rule('quality-default-credential', 'اعتماد افتراضي معروف', 'critical', 'المصادقة', /(?:admin|root|password|changeme|default)[=:]["'][^"']{4,}["']/i, 'قيمة تشبه اعتمادًا افتراضيًا.', 'قد تمنح دخولًا مباشرًا إذا بقيت في بيئة متصلة.', 'أزلها وطبّق enrollment أو secret rotation قبل الإصدار.', 'مسار التهديد: اعتماد افتراضي → تسجيل دخول → سيطرة على مورد.'),
];

const ALL_RULES: Rule[] = [...RULES, ...ADVANCED_RULES];
export const RULE_COUNT = ALL_RULES.length;

const TEXT_EXTENSIONS = /\.(?:xml|json|js|jsx|ts|tsx|java|kt|smali|txt|properties|gradle|pro|yml|yaml|html|htm|plist|swift|m|mm|c|cpp|h|hpp|md|map)$/i;
const MAX_ENTRY_BYTES = 180_000;
const MAX_FILES_TO_READ = 350;
const MAX_TOTAL_BYTES = 18_000_000;

const maskEvidence = (value: string): string =>
  value.length > 12 ? `${value.slice(0, 5)}••••${value.slice(-4)}` : 'قيمة حساسة محجوبة';

export async function scanArchive(
  zip: { files: Record<string, { dir: boolean; async: (type: 'string') => Promise<string> }> },
  fileName: string,
  sizeBytes: number,
): Promise<ScanReport> {
  const started = Date.now();
  const names = Object.keys(zip.files);
  const candidates = names
    .filter((name) => !zip.files[name]?.dir && (TEXT_EXTENSIONS.test(name) || /(?:AndroidManifest\.xml|classes\d*\.dex)$/i.test(name)))
    .slice(0, MAX_FILES_TO_READ);
  let scannedBytes = 0;
  const findings: ScanFinding[] = [];

  for (const name of candidates) {
    if (scannedBytes >= MAX_TOTAL_BYTES) break;
    try {
      const raw = await zip.files[name].async('string');
      const content = raw.slice(0, Math.min(raw.length, MAX_ENTRY_BYTES));
      scannedBytes += content.length;
      for (const candidate of ALL_RULES) {
        if (candidate.pattern.test(content)) {
          const match = content.match(candidate.pattern)?.[0] ?? candidate.title;
          candidate.pattern.lastIndex = 0;
          findings.push({
            id: candidate.id,
            title: candidate.title,
            severity: candidate.severity,
            category: candidate.category,
            summary: candidate.summary,
            evidence: maskEvidence(match.replace(/\s+/g, ' ').slice(0, 90)),
            impact: candidate.impact,
            fix: candidate.fix,
            learning: candidate.learning,
            verification: candidate.verification,
            references: candidate.references,
            attackSurface: candidate.attackSurface,
            confidence: candidate.confidence,
            file: name,
          });
        }
        candidate.pattern.lastIndex = 0;
      }
    } catch {
      // A binary entry can fail text decoding; skip it without crashing the scan.
    }
  }

  const deduped = Array.from(new Map(findings.map((item) => [`${item.id}:${item.file}`, item])).values());
  const limitations = [
    'الفحص النصي لا يحلّل bytecode أو الموارد الثنائية بشكل دلالي كاملًا.',
    'النتيجة مؤشر دفاعي وليست إثباتًا لوجود ثغرة أو غيابها.',
    'لا يتم فك تشفير الملفات المحمية ولا رفع أي محتوى خارج الجهاز.',
  ];
  if (candidates.length >= MAX_FILES_TO_READ || scannedBytes >= MAX_TOTAL_BYTES) {
    limitations.push(`تم تطبيق حد الأداء: ${MAX_FILES_TO_READ} ملفًا أو ${MAX_TOTAL_BYTES.toLocaleString()} بايت.`);
  }
  return {
    fileName,
    sizeBytes,
    scannedFiles: candidates.length,
    totalFiles: names.length,
    findings: deduped,
    categories: Array.from(new Set(deduped.map((item) => item.category))),
    durationMs: Date.now() - started,
    createdAt: new Date().toISOString(),
    rulesEvaluated: ALL_RULES.length,
    matchedRules: new Set(deduped.map((item) => item.id)).size,
    scannedBytes,
    limitations,
  };
}

export const severityWeight: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function getScore(report: ScanReport): number {
  const penalty = report.findings.reduce((sum, finding) => sum + severityWeight[finding.severity], 0);
  return Math.max(0, Math.min(100, 100 - penalty * 3));
}

export function getRiskLabel(score: number): string {
  if (score >= 85) return 'جيد';
  if (score >= 65) return 'يحتاج مراجعة';
  if (score >= 40) return 'مخاطر مرتفعة';
  return 'مخاطر حرجة';
}