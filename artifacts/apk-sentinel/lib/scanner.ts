export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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
      for (const candidate of RULES) {
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
  return {
    fileName,
    sizeBytes,
    scannedFiles: candidates.length,
    totalFiles: names.length,
    findings: deduped,
    categories: Array.from(new Set(deduped.map((item) => item.category))),
    durationMs: Date.now() - started,
    createdAt: new Date().toISOString(),
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