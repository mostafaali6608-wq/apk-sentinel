import { useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  ScrollView,
  Share,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import * as DocumentPicker from 'expo-document-picker';
import * as FileSystem from 'expo-file-system/legacy';
import * as Haptics from 'expo-haptics';
import JSZip from 'jszip';
import { Feather } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useColors } from '@/hooks/useColors';
import {
  getRiskLabel,
  getScore,
  RULE_COUNT,
  scanArchive,
  type ScanFinding,
  type ScanReport,
  type Severity,
} from '@/lib/scanner';

type ViewMode = 'overview' | 'findings' | 'learning' | 'inventory';
type HistoryItem = Pick<ScanReport, 'fileName' | 'sizeBytes' | 'findings' | 'createdAt'>;

const severityLabels: Record<Severity, string> = {
  critical: 'حرج',
  high: 'عالٍ',
  medium: 'متوسط',
  low: 'منخفض',
  info: 'معلومة',
};

const confidenceLabels = {
  high: 'ثقة مرتفعة',
  medium: 'ثقة متوسطة',
  low: 'ثقة منخفضة',
} as const;

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const scoreColor = (score: number, colors: ReturnType<typeof useColors>): string => {
  if (score >= 85) return colors.success;
  if (score >= 65) return colors.warning;
  if (score >= 40) return colors.high;
  return colors.critical;
};

function SeverityPill({ severity, colors }: { severity: Severity; colors: ReturnType<typeof useColors> }) {
  const color = colors[severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : severity === 'medium' ? 'warning' : severity === 'low' ? 'info' : 'mutedForeground'];
  return (
    <View style={[styles.pill, { backgroundColor: `${color}22` }]}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Text style={[styles.pillText, { color }]}>{severityLabels[severity]}</Text>
    </View>
  );
}

function FindingCard({ finding, colors }: { finding: ScanFinding; colors: ReturnType<typeof useColors> }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <Pressable
      testID={`finding-${finding.id}`}
      onPress={() => setExpanded((value) => !value)}
      style={({ pressed }) => [styles.findingCard, { backgroundColor: colors.card, borderColor: colors.border, opacity: pressed ? 0.88 : 1 }]}
    >
      <View style={styles.findingTop}>
        <View style={styles.findingIcon}>
          <Feather name={finding.severity === 'info' ? 'info' : 'alert-triangle'} size={17} color={colors[finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'high' : finding.severity === 'medium' ? 'warning' : 'info']} />
        </View>
        <View style={styles.findingTitleWrap}>
          <Text style={[styles.findingTitle, { color: colors.foreground }]}>{finding.title}</Text>
          <Text style={[styles.findingMeta, { color: colors.mutedForeground }]}>{finding.category} · {finding.file}</Text>
        </View>
        <SeverityPill severity={finding.severity} colors={colors} />
      </View>
      <Text style={[styles.findingSummary, { color: colors.secondaryForeground }]}>{finding.summary}</Text>
      {expanded ? (
        <View style={[styles.detailBox, { backgroundColor: colors.overlay, borderColor: colors.border }]}>
          <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>المؤشر المحجوب</Text>
          <Text selectable style={[styles.detailText, { color: colors.accentForeground }]}>{finding.evidence}</Text>
          <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>الأثر المحتمل</Text>
          <Text style={[styles.detailText, { color: colors.secondaryForeground }]}>{finding.impact}</Text>
          <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>الإصلاح المقترح</Text>
          <Text style={[styles.detailText, { color: colors.secondaryForeground }]}>{finding.fix}</Text>
          <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>مسار التهديد للتعلم</Text>
          <Text style={[styles.detailText, { color: colors.warning }]}>{finding.learning}</Text>
           <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>خطوة التحقق اليدوي</Text>
           <Text style={[styles.detailText, { color: colors.secondaryForeground }]}>{finding.verification}</Text>
           <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>سطح الهجوم · مستوى الثقة</Text>
           <Text style={[styles.detailText, { color: colors.accentForeground }]}>{finding.attackSurface} · {confidenceLabels[finding.confidence]}</Text>
           <Text style={[styles.detailLabel, { color: colors.mutedForeground }]}>مراجع دفاعية</Text>
           <Text style={[styles.detailText, { color: colors.secondaryForeground }]}>{finding.references.join(' · ')}</Text>
        </View>
      ) : (
        <Text style={[styles.expandHint, { color: colors.tint }]}>اضغط لعرض الأثر والإصلاح ومسار التهديد</Text>
      )}
    </Pressable>
  );
}

export default function HomeScreen() {
  const colors = useColors();
  const insets = useSafeAreaInsets();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [view, setView] = useState<ViewMode>('overview');
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [query, setQuery] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  const score = report ? getScore(report) : 0;
  const visibleFindings = useMemo(() => {
    if (!report) return [];
    return report.findings.filter((finding) => {
      const matchesSeverity = filter === 'all' || finding.severity === filter;
      const haystack = `${finding.title} ${finding.category} ${finding.file} ${finding.summary} ${finding.impact} ${finding.fix} ${finding.attackSurface}`.toLowerCase();
      return matchesSeverity && haystack.includes(query.toLowerCase());
    });
  }, [filter, query, report]);

  const pickAndScan = async () => {
    await Haptics.selectionAsync();
    try {
      const result = await DocumentPicker.getDocumentAsync({
        type: ['application/vnd.android.package-archive', 'application/zip', 'application/octet-stream'],
        copyToCacheDirectory: true,
        multiple: false,
      });
      if (result.canceled || !result.assets[0]) return;
      const asset = result.assets[0];
      setIsScanning(true);
      setView('overview');
      setReport(null);
      const base64 = await FileSystem.readAsStringAsync(asset.uri, { encoding: FileSystem.EncodingType.Base64 });
      const zip = await JSZip.loadAsync(base64, { base64: true, checkCRC32: false });
      const nextReport = await scanArchive(zip, asset.name, asset.size ?? 0);
      setReport(nextReport);
      setHistory((items) => [{ fileName: nextReport.fileName, sizeBytes: nextReport.sizeBytes, findings: nextReport.findings, createdAt: nextReport.createdAt }, ...items].slice(0, 6));
      await Haptics.notificationAsync(nextReport.findings.some((item) => item.severity === 'critical') ? Haptics.NotificationFeedbackType.Warning : Haptics.NotificationFeedbackType.Success);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'تعذر قراءة الملف';
      Alert.alert('تعذر الفحص', `تأكد أن الملف ZIP/APK/AAB صالح وغير مشفر.\n${message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const shareReport = async () => {
    if (!report) return;
    const grouped = (Object.keys(severityLabels) as Severity[]).map((severity) => `${severityLabels[severity]}: ${report.findings.filter((item) => item.severity === severity).length}`).join(' | ');
    await Share.share({
      title: `تقرير APK Sentinel - ${report.fileName}`,
      message: `APK Sentinel\nالملف: ${report.fileName}\nالنتيجة: ${score}/100 (${getRiskLabel(score)})\nالقواعد: ${report.rulesEvaluated} · المطابقة: ${report.matchedRules}\n${grouped}\n\nملاحظات الفحص:\n${report.findings.slice(0, 30).map((item) => `- [${severityLabels[item.severity]}] ${item.title}: ${item.fix}`).join('\n')}\n\nحدود الفحص:\n${report.limitations.join('\n')}`,
    });
  };

  const clearReport = () => {
    setReport(null);
    setView('overview');
    setFilter('all');
    setQuery('');
  };

  return (
    <View style={[styles.screen, { backgroundColor: colors.background }]}>
      <ScrollView
        contentContainerStyle={[styles.content, { paddingTop: insets.top + 18, paddingBottom: insets.bottom + 28 }]}
        showsVerticalScrollIndicator={false}
      >
        <View style={styles.header}>
          <View style={styles.brandMark}>
            <Feather name="shield" size={22} color={colors.primaryForeground} />
          </View>
          <View style={styles.brandText}>
            <Text style={[styles.eyebrow, { color: colors.tint }]}>DEFENSIVE MOBILE SECURITY</Text>
            <Text style={[styles.brand, { color: colors.foreground }]}>APK Sentinel</Text>
          </View>
          <View style={[styles.statusDot, { backgroundColor: colors.success }]} />
        </View>

        <View style={[styles.hero, { backgroundColor: colors.card, borderColor: colors.border }]}>
          <View style={styles.heroOrb} />
          <Text style={[styles.heroKicker, { color: colors.warning }]}>فحص محلي · لا رفع للملف</Text>
          <Text style={[styles.heroTitle, { color: colors.foreground }]}>اعرف ما بداخل حزمة تطبيقك قبل إطلاقها.</Text>
           <Text style={[styles.heroCopy, { color: colors.mutedForeground }]}>فاحص دفاعي يغطي {RULE_COUNT} قاعدة لمراجعة APK وAAB وZIP بحثًا عن أسرار، إعدادات خطرة، مؤشرات WebView وBilling وسلسلة تهديد قابلة للتعلم.</Text>
          <Pressable testID="pick-file" onPress={pickAndScan} disabled={isScanning} style={({ pressed }) => [styles.primaryButton, { backgroundColor: colors.primary, opacity: pressed || isScanning ? 0.72 : 1 }]}>
            {isScanning ? <ActivityIndicator color={colors.primaryForeground} /> : <Feather name="upload-cloud" size={19} color={colors.primaryForeground} />}
            <Text style={[styles.primaryButtonText, { color: colors.primaryForeground }]}>{isScanning ? 'جاري الفحص...' : 'اختر ملف APK أو AAB'}</Text>
          </Pressable>
          <Text style={[styles.privacyNote, { color: colors.mutedForeground }]}><Feather name="lock" size={12} color={colors.success} /> تتم القراءة داخل الجهاز فقط</Text>
        </View>

        {report ? (
          <>
            <View style={styles.sectionHeader}>
              <View>
                <Text style={[styles.sectionTitle, { color: colors.foreground }]}>ملخص الفحص</Text>
                <Text style={[styles.sectionSub, { color: colors.mutedForeground }]}>{report.fileName} · {formatBytes(report.sizeBytes || 0)}</Text>
              </View>
              <Pressable testID="share-report" onPress={shareReport} style={[styles.iconButton, { backgroundColor: colors.secondary }]}>
                <Feather name="share-2" size={18} color={colors.tint} />
              </Pressable>
            </View>

            <View style={[styles.scoreCard, { backgroundColor: colors.overlay, borderColor: colors.border }]}>
              <View style={styles.scoreRing}>
                <Text style={[styles.scoreNumber, { color: scoreColor(score, colors) }]}>{score}</Text>
                <Text style={[styles.scoreOutOf, { color: colors.mutedForeground }]}>/100</Text>
              </View>
              <View style={styles.scoreCopy}>
                <Text style={[styles.scoreLabel, { color: scoreColor(score, colors) }]}>{getRiskLabel(score)}</Text>
     <Text style={[styles.scoreDescription, { color: colors.secondaryForeground }]}>{report.findings.length ? `تم العثور على ${report.findings.length} مؤشرًا يحتاج للمراجعة.` : 'لم تظهر مؤشرات ضمن القواعد الحالية.'}</Text>
     <Text style={[styles.scoreMeta, { color: colors.mutedForeground }]}>{report.scannedFiles} ملف · {formatBytes(report.scannedBytes)} · {report.durationMs}ms</Text>
              </View>
            </View>

            <View style={styles.statRow}>
              {(['critical', 'high', 'medium'] as Severity[]).map((severity) => (
                <View key={severity} style={[styles.stat, { backgroundColor: colors.card, borderColor: colors.border }]}>
                  <Text style={[styles.statNumber, { color: colors[severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'warning'] }]}>{report.findings.filter((item) => item.severity === severity).length}</Text>
                  <Text style={[styles.statLabel, { color: colors.mutedForeground }]}>{severityLabels[severity]}</Text>
                </View>
              ))}
            </View>

            <View style={[styles.navBar, { backgroundColor: colors.card, borderColor: colors.border }]}>
              {([
                ['overview', 'grid', 'نظرة'],
                ['findings', 'alert-triangle', 'المؤشرات'],
                ['learning', 'book-open', 'التعلم'],
                ['inventory', 'list', 'الجرد'],
              ] as const).map(([key, icon, label]) => (
                <Pressable key={key} testID={`view-${key}`} onPress={() => setView(key)} style={[styles.navItem, view === key && { backgroundColor: colors.accent }]}>
                  <Feather name={icon} size={16} color={view === key ? colors.tint : colors.mutedForeground} />
                  <Text style={[styles.navLabel, { color: view === key ? colors.tint : colors.mutedForeground }]}>{label}</Text>
                </Pressable>
              ))}
            </View>

            {view === 'overview' && (
              <View style={[styles.panel, { backgroundColor: colors.card, borderColor: colors.border }]}>
                 <Text style={[styles.panelTitle, { color: colors.foreground }]}>تغطية الفحص المتقدمة</Text>
                 <Text style={[styles.panelIntro, { color: colors.mutedForeground }]}>تم تشغيل {report.rulesEvaluated} قاعدة دفاعية، وطابقت النتائج {report.matchedRules} قاعدة مختلفة. المطابقة مؤشر يحتاج تحققًا داخل المصدر أو artifact النهائي.</Text>
                 <View style={styles.checkRow}><Feather name="check-circle" size={18} color={colors.success} /><Text style={[styles.checkText, { color: colors.secondaryForeground }]}>أسرار واعتمادات وTokens وJWT وTelegram وواجهات API.</Text></View>
                <View style={styles.checkRow}><Feather name="check-circle" size={18} color={colors.success} /><Text style={[styles.checkText, { color: colors.secondaryForeground }]}>WebView وDeep Links وBilling وTelegram وPackers.</Text></View>
                 <View style={styles.checkRow}><Feather name="check-circle" size={18} color={colors.success} /><Text style={[styles.checkText, { color: colors.secondaryForeground }]}>Manifest وAndroid components والتخزين والتشفير والمصادقة والخصوصية.</Text></View>
                 <View style={styles.checkRow}><Feather name="check-circle" size={18} color={colors.success} /><Text style={[styles.checkText, { color: colors.secondaryForeground }]}>كل نتيجة تعرض المؤشر والأثر والإصلاح والتحقق والمراجع ومسار تهديد تعليمي.</Text></View>
                 <View style={[styles.coverageGrid, { borderTopColor: colors.border }]}>
                   <View><Text style={[styles.coverageNumber, { color: colors.tint }]}>{report.rulesEvaluated}</Text><Text style={[styles.coverageLabel, { color: colors.mutedForeground }]}>قاعدة فعّالة</Text></View>
                   <View><Text style={[styles.coverageNumber, { color: colors.warning }]}>{report.matchedRules}</Text><Text style={[styles.coverageLabel, { color: colors.mutedForeground }]}>قاعدة مطابقة</Text></View>
                   <View><Text style={[styles.coverageNumber, { color: colors.info }]}>{report.categories.length}</Text><Text style={[styles.coverageLabel, { color: colors.mutedForeground }]}>سطحًا</Text></View>
                 </View>
                <Pressable onPress={clearReport} style={[styles.secondaryButton, { borderColor: colors.border }]}>
                  <Feather name="refresh-cw" size={16} color={colors.tint} />
                  <Text style={[styles.secondaryButtonText, { color: colors.tint }]}>فحص ملف آخر</Text>
                </Pressable>
              </View>
            )}

            {view === 'findings' && (
              <View>
                <View style={[styles.searchBox, { backgroundColor: colors.card, borderColor: colors.border }]}>
                  <Feather name="search" size={17} color={colors.mutedForeground} />
                  <TextInput testID="finding-search" value={query} onChangeText={setQuery} placeholder="ابحث في المؤشرات أو الملفات" placeholderTextColor={colors.mutedForeground} style={[styles.searchInput, { color: colors.foreground }]} />
                </View>
                <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.filterRow}>
                  {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((item) => (
                    <Pressable key={item} onPress={() => setFilter(item)} style={[styles.filterChip, { borderColor: colors.border, backgroundColor: filter === item ? colors.accent : colors.card }]}>
                      <Text style={[styles.filterText, { color: filter === item ? colors.tint : colors.mutedForeground }]}>{item === 'all' ? 'الكل' : severityLabels[item]}</Text>
                    </Pressable>
                  ))}
                </ScrollView>
                {visibleFindings.length ? visibleFindings.map((finding) => <FindingCard key={`${finding.id}:${finding.file}`} finding={finding} colors={colors} />) : (
                  <View style={[styles.empty, { backgroundColor: colors.card, borderColor: colors.border }]}><Feather name="check-circle" size={28} color={colors.success} /><Text style={[styles.emptyTitle, { color: colors.foreground }]}>لا توجد نتائج بهذا الفلتر</Text><Text style={[styles.emptyText, { color: colors.mutedForeground }]}>جرّب تغيير مستوى الخطورة أو كلمة البحث.</Text></View>
                )}
              </View>
            )}

            {view === 'learning' && (
              <View style={[styles.panel, { backgroundColor: colors.card, borderColor: colors.border }]}>
                <Text style={[styles.panelTitle, { color: colors.foreground }]}>مسارات تهديد دفاعية</Text>
                <Text style={[styles.panelIntro, { color: colors.mutedForeground }]}>هذه المسارات تشرح كيف تفكر في الخطر من منظور دفاعي: مؤشر، أثر، ثم إصلاح. لا ينفذ التطبيق استغلالًا ولا يتجاوز حماية.</Text>
                 {report.findings.length ? report.findings.slice(0, 12).map((finding) => <View key={`${finding.id}:learning`} style={[styles.learningRow, { borderBottomColor: colors.border }]}><SeverityPill severity={finding.severity} colors={colors} /><View style={styles.learningCopy}><Text style={[styles.learningTitle, { color: colors.foreground }]}>{finding.title}</Text><Text style={[styles.learningText, { color: colors.warning }]}>{finding.learning}</Text><Text style={[styles.learningVerify, { color: colors.mutedForeground }]}>{finding.verification}</Text></View></View>) : <Text style={[styles.panelIntro, { color: colors.mutedForeground }]}>لا توجد مسارات تهديد مطابقة. هذا لا يثبت غياب المخاطر؛ راجع حدود الفحص والاختبارات الديناميكية.</Text>}
              </View>
            )}

            {view === 'inventory' && (
              <View style={[styles.panel, { backgroundColor: colors.card, borderColor: colors.border }]}>
                <Text style={[styles.panelTitle, { color: colors.foreground }]}>جرد الحزمة</Text>
                <Text style={[styles.panelIntro, { color: colors.mutedForeground }]}>تمت قراءة {report.scannedFiles} من أصل {report.totalFiles} ملفًا نصيًا أو قابلًا للاستخراج ضمن حدود أداء آمنة.</Text>
                {report.categories.map((category) => <View key={category} style={[styles.inventoryRow, { borderBottomColor: colors.border }]}><Feather name="folder" size={16} color={colors.tint} /><Text style={[styles.inventoryText, { color: colors.secondaryForeground }]}>{category}</Text><Text style={[styles.inventoryCount, { color: colors.mutedForeground }]}>{report.findings.filter((item) => item.category === category).length}</Text></View>)}
                 {report.limitations.map((limitation) => <View key={limitation} style={[styles.limitNote, { backgroundColor: colors.overlay }]}><Feather name="info" size={15} color={colors.info} /><Text style={[styles.limitText, { color: colors.mutedForeground }]}>{limitation}</Text></View>)}
              </View>
            )}
          </>
        ) : (
          <View style={[styles.startPanel, { borderColor: colors.border }]}>
            <View style={[styles.startIcon, { backgroundColor: colors.accent }]}><Feather name="crosshair" size={24} color={colors.tint} /></View>
            <Text style={[styles.startTitle, { color: colors.foreground }]}>ابدأ بفحص أول حزمة</Text>
            <Text style={[styles.startText, { color: colors.mutedForeground }]}>اختر ملفًا من الهاتف. سيبقى المحتوى داخل الجهاز، وستحصل على تقرير عملي قابل للمشاركة.</Text>
            {!!history.length && <Text style={[styles.historyTitle, { color: colors.mutedForeground }]}>آخر الفحوصات في هذه الجلسة</Text>}
            {history.map((item) => <View key={`${item.fileName}:${item.createdAt}`} style={[styles.historyRow, { borderTopColor: colors.border }]}><Feather name="file" size={16} color={colors.tint} /><Text numberOfLines={1} style={[styles.historyName, { color: colors.secondaryForeground }]}>{item.fileName}</Text><Text style={[styles.historyCount, { color: colors.mutedForeground }]}>{item.findings.length} مؤشرات</Text></View>)}
          </View>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  content: { paddingHorizontal: 18, gap: 16 },
  header: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  brandMark: { width: 42, height: 42, borderRadius: 14, alignItems: 'center', justifyContent: 'center', backgroundColor: '#43D9FF' },
  brandText: { flex: 1 },
  eyebrow: { fontSize: 10, fontWeight: '700', letterSpacing: 1.5 },
  brand: { fontSize: 23, fontWeight: '700', letterSpacing: -0.5 },
  statusDot: { width: 9, height: 9, borderRadius: 9 },
  hero: { overflow: 'hidden', borderRadius: 24, borderWidth: 1, padding: 22, gap: 12 },
  heroOrb: { position: 'absolute', width: 170, height: 170, borderRadius: 170, right: -55, top: -55, backgroundColor: '#1A3147' },
  heroKicker: { fontSize: 12, fontWeight: '600' },
  heroTitle: { fontSize: 28, lineHeight: 34, fontWeight: '700', maxWidth: 330, letterSpacing: -0.8 },
  heroCopy: { fontSize: 14, lineHeight: 22 },
  primaryButton: { minHeight: 50, borderRadius: 15, paddingHorizontal: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 9, marginTop: 4 },
  primaryButtonText: { fontSize: 15, fontWeight: '700' },
  privacyNote: { fontSize: 11, textAlign: 'center' },
  sectionHeader: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  sectionTitle: { fontSize: 21, fontWeight: '700' },
  sectionSub: { fontSize: 12, marginTop: 3 },
  iconButton: { width: 42, height: 42, borderRadius: 14, alignItems: 'center', justifyContent: 'center' },
  scoreCard: { borderRadius: 20, borderWidth: 1, padding: 18, flexDirection: 'row', alignItems: 'center', gap: 17 },
  scoreRing: { width: 90, height: 90, borderRadius: 45, borderWidth: 5, borderColor: '#203650', alignItems: 'center', justifyContent: 'center', flexDirection: 'row' },
  scoreNumber: { fontSize: 30, fontWeight: '700' },
  scoreOutOf: { fontSize: 11, marginTop: 14 },
  scoreCopy: { flex: 1, gap: 5 },
  scoreLabel: { fontSize: 19, fontWeight: '700' },
  scoreDescription: { fontSize: 13, lineHeight: 19 },
  scoreMeta: { fontSize: 11 },
  statRow: { flexDirection: 'row', gap: 10 },
  stat: { flex: 1, borderRadius: 16, borderWidth: 1, padding: 13, gap: 3 },
  statNumber: { fontSize: 25, fontWeight: '700' },
  statLabel: { fontSize: 12 },
  coverageGrid: { borderTopWidth: 1, paddingTop: 13, flexDirection: 'row', justifyContent: 'space-between' },
  coverageNumber: { fontSize: 21, fontWeight: '700' },
  coverageLabel: { fontSize: 11, marginTop: 2 },
  navBar: { borderRadius: 16, borderWidth: 1, padding: 5, flexDirection: 'row', gap: 4 },
  navItem: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 5, paddingVertical: 9, borderRadius: 12 },
  navLabel: { fontSize: 11, fontWeight: '600' },
  panel: { borderRadius: 20, borderWidth: 1, padding: 18, gap: 15 },
  panelTitle: { fontSize: 18, fontWeight: '700' },
  panelIntro: { fontSize: 13, lineHeight: 21 },
  checkRow: { flexDirection: 'row', gap: 10, alignItems: 'flex-start' },
  checkText: { flex: 1, fontSize: 13, lineHeight: 20 },
  secondaryButton: { minHeight: 44, borderRadius: 13, borderWidth: 1, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8, marginTop: 3 },
  secondaryButtonText: { fontSize: 14, fontWeight: '600' },
  searchBox: { minHeight: 48, borderRadius: 14, borderWidth: 1, paddingHorizontal: 14, flexDirection: 'row', alignItems: 'center', gap: 9 },
  searchInput: { flex: 1, fontSize: 14 },
  filterRow: { gap: 8, paddingVertical: 1 },
  filterChip: { borderWidth: 1, borderRadius: 20, paddingHorizontal: 14, paddingVertical: 9 },
  filterText: { fontSize: 12, fontWeight: '600' },
  findingCard: { borderRadius: 18, borderWidth: 1, padding: 15, gap: 11 },
  findingTop: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  findingIcon: { width: 32, height: 32, borderRadius: 11, backgroundColor: '#1A3147', alignItems: 'center', justifyContent: 'center' },
  findingTitleWrap: { flex: 1, gap: 3 },
  findingTitle: { fontSize: 14, fontWeight: '700', lineHeight: 19 },
  findingMeta: { fontSize: 10 },
  findingSummary: { fontSize: 13, lineHeight: 20 },
  pill: { borderRadius: 20, paddingHorizontal: 8, paddingVertical: 5, flexDirection: 'row', alignItems: 'center', gap: 5 },
  dot: { width: 6, height: 6, borderRadius: 6 },
  pillText: { fontSize: 10, fontWeight: '700' },
  expandHint: { fontSize: 11, fontWeight: '600' },
  detailBox: { borderRadius: 13, borderWidth: 1, padding: 12, gap: 5 },
  detailLabel: { fontSize: 10, fontWeight: '700', marginTop: 4 },
  detailText: { fontSize: 12, lineHeight: 19 },
  empty: { borderRadius: 18, borderWidth: 1, padding: 28, alignItems: 'center', gap: 9 },
  emptyTitle: { fontSize: 16, fontWeight: '700' },
  emptyText: { fontSize: 13, textAlign: 'center' },
  learningRow: { borderBottomWidth: 1, paddingVertical: 10, flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  learningCopy: { flex: 1, gap: 5 },
  learningTitle: { fontSize: 13, fontWeight: '700' },
  learningText: { fontSize: 12, lineHeight: 18 },
  learningVerify: { fontSize: 11, lineHeight: 17, marginTop: 2 },
  inventoryRow: { borderBottomWidth: 1, paddingVertical: 11, flexDirection: 'row', gap: 10, alignItems: 'center' },
  inventoryText: { flex: 1, fontSize: 13 },
  inventoryCount: { fontSize: 12 },
  limitNote: { borderRadius: 12, padding: 12, flexDirection: 'row', gap: 8, alignItems: 'flex-start' },
  limitText: { flex: 1, fontSize: 11, lineHeight: 17 },
  startPanel: { borderRadius: 20, borderWidth: 1, borderStyle: 'dashed', padding: 22, alignItems: 'center', gap: 11 },
  startIcon: { width: 56, height: 56, borderRadius: 19, alignItems: 'center', justifyContent: 'center', marginBottom: 2 },
  startTitle: { fontSize: 18, fontWeight: '700' },
  startText: { fontSize: 13, lineHeight: 21, textAlign: 'center' },
  historyTitle: { alignSelf: 'flex-start', fontSize: 12, fontWeight: '600', marginTop: 8 },
  historyRow: { width: '100%', borderTopWidth: 1, paddingTop: 11, flexDirection: 'row', alignItems: 'center', gap: 9 },
  historyName: { flex: 1, fontSize: 12 },
  historyCount: { fontSize: 11 },
});