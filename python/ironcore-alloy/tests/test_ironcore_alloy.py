import base64
from ironcore_alloy import *  # pyright: ignore[reportWildcardImportFromLibrary]
import pytest


class TestIroncoreAlloy:
    key_bytes = "hJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yA=".encode("utf-8")
    key_bytes2 = "iJdwvEeg5mxTu9qWcWrljfKs1ga4MpQ9MzXgLxtlkwX//yB=".encode("utf-8")
    scaling_factor = 12345.0
    approximation_factor = 1.1
    standard_secrets = StandardSecrets(10, [StandaloneSecret(10, Secret(key_bytes))])
    deterministic_secrets = {
        "": RotatableSecret(
            StandaloneSecret(2, Secret(key_bytes)),
            StandaloneSecret(1, Secret(key_bytes2)),
        )
    }
    vector_secrets = {
        "": VectorSecret(
            approximation_factor,
            RotatableSecret(
                StandaloneSecret(2, Secret(key_bytes)),
                StandaloneSecret(1, Secret(key_bytes)),
            ),
        )
    }
    config = StandaloneConfiguration(
        standard_secrets, deterministic_secrets, vector_secrets
    )
    sdk = Standalone(config)

    # Tests using this are skipped by default. Unskip them as needed
    integration_sdk = SaasShield(
        SaasShieldConfiguration(
            "http://localhost:32804", "0WUaXesNgbTAuLwn", False, 1.1
        )
    )

    def test_floating_point_math(self):
        pass

    @pytest.mark.asyncio
    async def test_roundtrip_vector(self):
        plaintext = PlaintextVector(plaintext_vector=[-0.09970594197511673, 0.2759823203086853, -0.09934346377849579, -0.262724369764328, -0.04983067512512207, -0.06822530180215836, -0.04946443811058998, -0.11219743639230728, 0.2017967402935028, 0.044573962688446045, 0.02176917903125286, -0.04466402530670166, -0.23892097175121307, 0.09744075685739517, -0.35056179761886597, 0.3330576717853546, 0.2576199471950531, 0.14263971149921417, -0.11110004037618637, 0.39188244938850403, 0.11111016571521759, -0.20027755200862885, 0.18088075518608093, -0.16216842830181122, 0.11554624885320663, -0.1607309728860855, -0.0056117526255548, -0.1172993928194046, -0.07765751332044601, -0.11170054227113724, 0.2064134031534195, -0.3080829977989197, 0.20592530071735382, -0.11678152531385422, 0.16169103980064392, 0.3340438902378082, -0.11809849739074707, 0.033937182277441025, -0.20959292352199554, -0.22507742047309875, -0.10850531607866287, -0.09886761009693146, 0.09076578915119171, 0.10414009541273117, 0.2017858326435089, 0.19691719114780426, -0.29630932211875916, -0.19716213643550873, -0.024534765630960464, -0.13314762711524963, 0.11618763208389282, -0.21286003291606903, -0.29939982295036316, -0.10718641430139542, -0.3559620678424835, -0.4073384702205658, -0.21555879712104797, 0.5101987719535828, -0.47773560881614685, 0.30626776814460754, -0.2549329400062561, 0.05708303675055504, -0.21287545561790466, 0.2898419499397278, -0.08769746869802475, -0.06364056468009949, 0.20933648943901062, 0.48334500193595886, -0.1433221995830536, 0.1686544567346573, 0.2197134792804718, -0.35081782937049866, -0.23735591769218445, 0.0931498184800148, -0.10479389131069183, 0.19691483676433563, -0.097862608730793, 0.3620409071445465, -0.2756395936012268, -0.1245373860001564, -0.20268996059894562, -0.07953020185232162, 0.09186601638793945, -0.1977252960205078, -0.11827494204044342, 0.0052343690767884254, -0.13701482117176056, -0.036199770867824554, 0.2680126130580902, -0.711958110332489, -0.17897410690784454, -0.010420108214020729, 0.12610375881195068, -0.22125308215618134, 0.08040172606706619, -0.3591735064983368, -0.13565388321876526, 0.13254739344120026, -0.394864946603775, -0.39153602719306946, 0.0755964145064354, -0.02349894680082798, 0.006655125878751278, 0.2829711437225342, 0.04146397486329079, 0.3702307343482971, 0.08679116517305374, -0.11631134897470474, -0.18641415238380432, -0.10505502671003342, 0.07396988570690155, -0.28144967555999756, 0.33760306239128113, 0.04427502676844597, -0.28323546051979065, 0.2864041328430176, -0.3166283965110779, -0.022687483578920364, 0.39081957936286926, -0.1290973275899887, 0.04949399456381798, 0.0403357557952404, 0.026398370042443275, -0.18256361782550812, 0.07404514402151108, -0.1460229456424713, -0.13553641736507416, -0.25623854994773865, 0.14273740351200104, -0.17251035571098328, -0.26093021035194397, -0.15785518288612366, 0.3589688837528229, -0.03717638924717903, -0.29699406027793884, 0.0027279877103865147, -0.1703716516494751, 0.3752346336841583, -0.33083799481391907, 0.11776068061590195, 0.324126660823822, -0.35117313265800476, -0.13263548910617828, -0.31846076250076294, -0.1204119473695755, 0.1413835734128952, 0.42531639337539673, -0.0693875104188919, 0.06345058232545853, 0.484331876039505, 0.19677701592445374, 0.25641196966171265, 0.11766482889652252, 0.2790859341621399, -0.18465082347393036, 0.20601920783519745, 0.07507561892271042, 0.13185299932956696, -0.33046436309814453, 0.018576180562376976, -0.420803964138031, 0.15555457770824432, 0.3095397651195526, 0.21296535432338715, 0.020707419142127037, 0.5572517514228821, -0.16988559067249298, 0.17472155392169952, 0.022461380809545517, -0.40161022543907166, -0.04367456212639809, 0.10224173218011856, 0.1488947570323944, 0.008490639738738537, 0.13014759123325348, 0.21098434925079346, -0.29836535453796387, -0.1516633778810501, -0.2539981007575989, -0.2680848240852356, 0.3374035060405731, 0.39286109805107117, 0.15931662917137146, 0.007831167429685593, 0.18467150628566742, 0.04942015931010246, -0.10914033651351929, -0.33477187156677246, 0.2426082342863083, 0.1008763387799263, -0.05037689581513405, -0.077055923640728, -0.11219541728496552, -0.02122589386999607, -0.1996828019618988, -0.09470073133707047, 0.12877610325813293, -0.09639996290206909, 0.1225442886352539, -0.1134679988026619, 0.12501190602779388, 0.0644267275929451, 0.018908681347966194, -0.20996418595314026, 0.24592794477939606, -0.005648324731737375, -0.08770142495632172, -0.2732942998409271, 0.08618088066577911, -0.39637622237205505, 0.05018344148993492, -0.1963406652212143, 0.11372844874858856, -0.20812277495861053, 0.28476661443710327, -0.3341328799724579, 0.15987999737262726, 0.02889094315469265, -0.038458287715911865, -0.03960052505135536, 0.20865269005298615, 0.05400766059756279, -0.3549390733242035, 0.02927425131201744, 0.291585773229599, -0.4535941481590271, 0.18317456543445587, -0.012816531583666801, 0.0790552869439125, -0.12416987121105194, 0.047119140625, 0.2488463670015335, 0.3497009873390198, -0.3169229030609131, -0.021841512992978096, -0.16108889877796173, -0.45881104469299316, 0.07991286367177963, -0.07338669151067734, -0.14762279391288757, 0.28333544731140137, -0.26248812675476074, 0.2668563425540924, -0.256904274225235, 0.0706222653388977, 0.15833629667758942, 0.12018194049596786, 0.07698797434568405, -0.04532032087445259, 0.3777464032173157, 0.1761273443698883, -0.19466078281402588, -0.03154601901769638, -0.021379360929131508, 0.1093999594449997, 0.2147935926914215, 0.20986439287662506, 0.09348993748426437, -0.13003544509410858, -0.0358569398522377, 0.244691863656044, 0.15883375704288483, -0.21337547898292542, -0.19275932013988495, 0.06534742563962936, -0.004690662957727909, 0.5103129744529724, -0.048147570341825485, -0.054332178086042404, 0.1524961292743683, -0.11843568831682205, -0.2492399364709854, -0.4611227810382843, 0.10231137275695801, -0.3411276042461395, -0.19199658930301666, 0.3235817551612854, -0.13877713680267334, -0.2086954265832901, 0.041697077453136444, -0.20060108602046967, -0.23286379873752594, -0.5781806707382202, -0.06551487743854523, -0.23957861959934235, 0.10085214674472809, 0.11933877319097519, -0.018791276961565018, -0.36441487073898315, -0.007859945297241211, 0.1935161054134369, -0.06201544031500816, -0.33161166310310364, 0.19192205369472504, 0.1281350553035736, -0.18645226955413818, -0.18352870643138885, 0.05747721344232559, 0.08758760243654251, -1.19746994972229, -0.22046199440956116, 0.27024710178375244, 0.11982411891222, 0.24880780279636383, -0.202640563249588, -0.16965194046497345, -0.0005678236484527588, -0.00020229816436767578, 0.2477538287639618, 0.4413948059082031, 0.33361679315567017, 0.07106659561395645, -0.13857822120189667, 0.024257076904177666, 0.23606370389461517, -0.09179366379976273, -0.05018400028347969, 0.35170191526412964, 0.054984815418720245, 0.16553352773189545, 0.3187583088874817, 0.006925799418240786, 0.22972659766674042, -0.07048673927783966, -0.0040203845128417015, -0.13924267888069153, -0.09011898934841156, -0.017075147479772568, -0.37929993867874146, 0.011870570480823517, -0.0681958720088005, 0.12834736704826355, -0.1342284381389618, 0.12861227989196777, -0.2265671193599701, 0.03480574116110802, -0.12716270983219147, -0.4190669357776642, -0.07526534050703049, -0.16385462880134583, -0.07564936578273773, -0.371711790561676, 0.16731183230876923, 0.09453720599412918, -0.06679954379796982, -0.1362908035516739, 0.10622172802686691, 0.2026987224817276, -0.25524193048477173, -0.6074021458625793, 0.3068248927593231, 0.06692729145288467, -0.10704860836267471, -0.5157159566879272, 0.1091732382774353, 0.7133592367172241, 0.12136337906122208, -0.3619707524776459, 0.3549629747867584, -0.1528254598379135, -0.23686042428016663, 0.00705116568133235, -0.2886357307434082, -0.03404379263520241, 0.10960876941680908, 0.5816280245780945, -0.17025908827781677, 0.36961835622787476, -0.10665187984704971, 0.3368111550807953, 0.12002932280302048, 0.034688301384449005, 0.6994503140449524, -0.03649774193763733, -0.14213350415229797, -0.16606466472148895, 0.22665123641490936, 0.36678075790405273, 0.5227711796760559, -0.11264437437057495, 0.02796562947332859, -0.026620378717780113, 0.04550529643893242, -0.02718201093375683, -0.011379857547581196, 0.05355540290474892, -0.28585657477378845, -0.18938006460666656, 0.1011744812130928, -0.12373016029596329, -0.0853346735239029, -0.4760832190513611, 0.22222070395946503, 0.23150065541267395, -0.34438106417655945, -0.25470441579818726, 0.14548741281032562, 0.060388486832380295, 0.090259850025177, 0.14740614593029022, 0.3441948890686035, 0.2848626971244812, 0.021205604076385498, -0.009171376004815102, -0.020952459424734116, 0.08360487967729568, -0.10687381029129028, -0.08147553354501724, -0.023690877482295036, 0.336472749710083, -0.010566292330622673, -0.04270472005009651, 0.17086823284626007, -0.046026069670915604, -0.12542761862277985, -0.0720985159277916, 0.21939705312252045, 0.17445982992649078, 0.1776765137910843, -0.34303078055381775, -0.047150615602731705, 0.24880678951740265, 0.09140409529209137, -0.17307400703430176, 0.09872674942016602, 0.15867669880390167, 0.014734874479472637, -0.04211784154176712, -0.17045773565769196, -0.16100060939788818, 0.17468856275081635, -0.3727962374687195, 0.15834490954875946, 0.1299603432416916, 0.8231185078620911, 0.48397770524024963, 0.29423287510871887, 0.2895919382572174, -0.08153947442770004, 0.2755962312221527, 0.3363860547542572, -0.36762315034866333, 0.32512474060058594, 0.23445811867713928, -0.4203917682170868, -0.37314727902412415, 0.3420540988445282, 0.2386082112789154, -0.22651319205760956, -0.031418923288583755, -0.07520812749862671, -0.08935762941837311, -0.00028827149071730673, 0.33363965153694153, -0.3197973668575287, 0.21097837388515472, 0.1141289696097374, -0.0575372651219368, -0.017878754064440727, -0.1967027634382248, 0.5058956742286682, -0.01743813045322895, 0.2511692941188812, -0.28391578793525696, -0.19799469411373138, -0.4003887474536896, -0.25108247995376587, 0.06611534208059311, 0.171072855591774, 0.009299101307988167, 0.3869906961917877, 0.2137186974287033, -0.13561543822288513, 0.1456271857023239, 0.025506243109703064, -0.0998995304107666, -0.29517659544944763, 0.016729000955820084, 0.07370192557573318, 0.0018050606595352292, -0.1535920947790146, 0.1356600821018219, 0.3231887221336365, -0.22093023359775543, -0.4289567172527313, 0.10327678173780441, -0.13214680552482605, 0.101357102394104, 0.02954159490764141, -0.1430896520614624, -0.17405124008655548, 0.34572649002075195, 0.02704620361328125, 0.5117413401603699, -0.5021723508834839, 0.14382807910442352, -0.02166195772588253, -0.11616333574056625, -0.25488367676734924, 0.1087217926979065, 0.41310977935791016, 0.2264634221792221, 0.1500893086194992, -0.2450839728116989, -0.04581831023097038, -0.09659115970134735, -0.2919122278690338, -0.25789040327072144, -0.057483017444610596, 0.35646483302116394, -0.030053643509745598, -0.1501907855272293, -0.3119976818561554, -0.03379077836871147, -0.20583486557006836, 0.06893809139728546, -0.5497538447380066, -0.5316206216812134, -0.011436685919761658, 0.005322714801877737, 0.2906501293182373, -0.6011948585510254, -0.3273932635784149, 0.0076788440346717834, -0.33722591400146484, -0.2852574288845062, 0.2500445246696472, -0.04526939243078232, -0.21699018776416779, 0.16112710535526276, -0.3535479009151459, -0.03268064931035042, -0.027176331728696823, -0.2776981294155121, 0.14027824997901917, -0.12540200352668762, 0.24199065566062927, 0.5588182210922241, -0.2033248096704483, 0.1265057623386383, -0.11342418193817139, -0.19799353182315826, -0.5352728962898254, -0.4017372131347656, 0.43311163783073425, -0.19702236354351044, -0.06635837256908417, -0.046124737709760666, 0.13821421563625336, 0.22883959114551544, 0.0021068076603114605, 0.14988064765930176, -0.6354584097862244, 0.49965959787368774, 0.15767839550971985, 0.004295621532946825, 0.040477652102708817, -0.002255890052765608, -0.012558085843920708, -0.016824882477521896, -0.4361898601055145, -0.26051682233810425, -0.03876848891377449, 0.2813906967639923, -0.22703087329864502, -0.04820873960852623, 0.17756786942481995, 0.24948212504386902, -0.022714855149388313, -0.039133261889219284, 0.04758384823799133, -0.1610240638256073, 0.1892164796590805, 0.05560484528541565, -0.14405564963817596, -0.5594934821128845, 0.3285789489746094, 0.21513567864894867, -0.05069619417190552, 0.07635370641946793, 0.1080208346247673, -0.25307968258857727, 0.6195191144943237, 0.01677284762263298, -0.047609973698854446, 0.04049491882324219, -0.3213207721710205, 0.13173753023147583, 0.36451444029808044, -0.09254647046327591, 0.3166174292564392, 0.3722142279148102, 0.16981759667396545, -0.18565323948860168, -0.01413851510733366, -0.2061336487531662, -0.1316743791103363, 0.12553706765174866, -0.14020805060863495, -0.1626921147108078, 0.005173271056264639, -0.029646113514900208, 0.264710396528244, 0.06492440402507782, -0.027474533766508102, -0.137658029794693, 0.16110847890377045, 0.21455298364162445, -0.03786919638514519, 0.1294381469488144, 0.11164486408233643, -0.01418997161090374, -0.03910759463906288, 0.13360929489135742, 0.11720672994852066, -0.0664987713098526, -0.15685106813907623, 0.3599728047847748, 0.24934959411621094, -0.4190017879009247, -0.20489229261875153, 0.0029123893473297358, 0.22382760047912598, 0.07145248353481293, -0.3827996253967285, -0.12999971210956573, -0.11824672669172287, -0.0572795532643795, 0.143403559923172, 0.07777233421802521, 0.3321278691291809, -0.06220467761158943, -0.05389389023184776, -0.2803378403186798, -0.25373491644859314, -0.027132118120789528, -0.005638406611979008, 0.14696700870990753, -0.001135151251219213, -0.49978092312812805, -0.20319901406764984, 0.44051292538642883, 0.37906184792518616, -0.34793972969055176, 0.05637456849217415, 0.1553952544927597, -0.16295196115970612, 0.10998731851577759, 0.037684302777051926, 0.17333902418613434, 0.045155610889196396, -0.05251717194914818, -0.16599063575267792, 0.36010605096817017, -0.3567585051059723, 0.19481906294822693, -0.4186909794807434, -0.2918172776699066, -0.1189088225364685, 0.22692210972309113, 0.1837889403104782, -0.2736310660839081, 0.4380015730857849, -0.11351235955953598, -0.37981703877449036, 0.010972834192216396, 0.2660733759403229, 0.04969429224729538, 0.2860408127307892, -0.16658784449100494, 0.0789484828710556, 0.3151266574859619, 0.18609817326068878, 0.06232263892889023, 0.04989943280816078, -0.12581484019756317, 0.11559610068798065, -0.5159115195274353, 0.016146864742040634, 0.30468136072158813, -0.006156879011541605, 0.0518176443874836, 0.2270362228155136, 0.22421900928020477, -0.07187698036432266, -0.49540284276008606, 0.2676217555999756, -0.25767582654953003, 0.5254297256469727, 0.3319450914859772, -0.15770582854747772, 0.43710729479789734, 0.12226714938879013, -0.1492960900068283, 0.04660215228796005, 0.45636752247810364, 0.3347759544849396, -0.0033901387359946966, 0.028621623292565346, -0.001758463098667562, -0.5892257690429688, 0.026938889175653458, -0.05915996804833412, 0.3318009674549103, 0.24545836448669434, 0.15059253573417664, -0.44400647282600403, -0.05291372537612915, 0.24988557398319244, 0.01661871001124382, 0.07505878061056137, 0.17003491520881653, 0.11414668709039688, 0.04992238059639931, 0.12951059639453888, -0.03149794414639473, 0.124763622879982, 0.3852410912513733, -0.0690237283706665, 0.07227303087711334, -0.009091873653233051, -0.06989950686693192, 0.02496199496090412, 0.03369024023413658, -0.15311522781848907, -0.07915835827589035, 0.38159385323524475, 0.006364934612065554, 0.40537452697753906, 0.502639651298523, -0.046438224613666534, -0.10046005249023438, -0.07060830295085907, 0.4265686571598053, 0.10256076604127884, -0.0514802522957325, -0.326386958360672, 0.31837743520736694, 0.08369620144367218, 0.09003806114196777, -0.03388059884309769, 0.12786579132080078, 0.08794301003217697, 0.34570246934890747, 0.5041595101356506, -0.11289657652378082, -0.10676238685846329, -0.05554737523198128, 0.25772470235824585, 0.054320432245731354, -0.1692589670419693, -0.34426149725914, -0.1056165099143982, -0.2824418246746063, 0.029607081785798073, -0.17326755821704865, -0.23512904345989227, 0.13412579894065857, -0.036894164979457855, -0.0276521984487772, -0.5816997289657593, 0.20207162201404572, 0.06510765105485916, -0.154845729470253, 0.0705125629901886, 0.2748737633228302, -0.5959886312484741, 0.16181661188602448], 
                                    secret_path="", derivation_path="")  # fmt: skip
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.vector().encrypt(plaintext, metadata)
        assert encrypted.encrypted_vector != plaintext.plaintext_vector
        decrypted = await self.sdk.vector().decrypt(encrypted, metadata)
        assert decrypted.plaintext_vector == pytest.approx(
            plaintext.plaintext_vector, rel=1e-5
        )

    @pytest.mark.asyncio
    async def test_decrypt_vector(self):
        ciphertext = [5826192.0, 15508204.0, 11420345.0]
        metadata = AlloyMetadata.new_simple("tenant")
        icl_metadata = base64.b64decode(
            b"AAAAAoEACgyVAnirL57DGDIdC28SIH9FFpmMs5yi5CcTcQjcUjldEE0OEdZDWtpyNI++ALnf"
        )
        encrypted_value = EncryptedVector(
            encrypted_vector=ciphertext,
            secret_path="",
            derivation_path="",
            paired_icl_info=icl_metadata,
        )
        decrypted = await self.sdk.vector().decrypt(encrypted_value, metadata)
        assert decrypted.plaintext_vector == [1.0, 2.0, 3.0]

    @pytest.mark.asyncio
    async def test_vector_batch_roundtrip(self):
        plaintext_input = [0.1, 0.2, 0.3]
        vector = PlaintextVector(
            plaintext_vector=plaintext_input, secret_path="", derivation_path=""
        )
        bad_vector = PlaintextVector(
            plaintext_vector=plaintext_input,
            secret_path="bad_path",
            derivation_path="bad_path",
        )
        vectors = {"vec": vector, "bad_vec": bad_vector}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.vector().encrypt_batch(vectors, metadata)
        assert len(encrypted.successes) == 1
        assert len(encrypted.failures) == 1
        assert (
            encrypted.failures["bad_vec"].msg  # type: ignore
            == "Provided secret path `bad_path` does not exist in the vector configuration."
        )
        decrypted = await self.sdk.vector().decrypt_batch(encrypted.successes, metadata)
        assert len(decrypted.successes) == 1
        assert len(decrypted.failures) == 0
        assert decrypted.successes["vec"].plaintext_vector == pytest.approx(
            plaintext_input, rel=1e-5
        )

    @pytest.mark.asyncio
    async def test_rotate_vector_different_tenant(self):
        ciphertext = [5826192.0, 15508204.0, 11420345.0]
        metadata = AlloyMetadata.new_simple("tenant")
        icl_metadata = base64.b64decode(
            b"AAAAAoEACgyVAnirL57DGDIdC28SIH9FFpmMs5yi5CcTcQjcUjldEE0OEdZDWtpyNI++ALnf"
        )
        encrypted_vector = EncryptedVector(
            encrypted_vector=ciphertext,
            secret_path="",
            derivation_path="",
            paired_icl_info=icl_metadata,
        )
        vectors = {"vector": encrypted_vector}
        metadata = AlloyMetadata.new_simple("tenant")
        rotated = await self.sdk.vector().rotate_vectors(vectors, metadata, "tenant2")
        assert len(rotated.successes) == 1
        assert len(rotated.failures) == 0
        new_metadata = AlloyMetadata.new_simple("tenant2")
        decrypted = await self.sdk.vector().decrypt(
            rotated.successes["vector"], new_metadata
        )
        assert decrypted.plaintext_vector == pytest.approx([1.0, 2.0, 3.0], rel=1e-5)

    @pytest.mark.asyncio
    async def test_rotate_vector_different_key(self):
        vector_secrets2 = {
            "": VectorSecret(
                self.approximation_factor,
                # Switched current and in-rotation versus original sdk
                RotatableSecret(
                    StandaloneSecret(1, Secret(self.key_bytes)),
                    StandaloneSecret(2, Secret(self.key_bytes)),
                ),
            )
        }
        sdk2 = Standalone(
            StandaloneConfiguration(
                self.standard_secrets, self.deterministic_secrets, vector_secrets2
            )
        )
        ciphertext = [5826192.0, 15508204.0, 11420345.0]
        metadata = AlloyMetadata.new_simple("tenant")
        icl_metadata = base64.b64decode(
            b"AAAAAoEACgyVAnirL57DGDIdC28SIH9FFpmMs5yi5CcTcQjcUjldEE0OEdZDWtpyNI++ALnf"
        )
        encrypted_vector = EncryptedVector(
            encrypted_vector=ciphertext,
            secret_path="",
            derivation_path="",
            paired_icl_info=icl_metadata,
        )
        vectors = {"vector": encrypted_vector}
        metadata = AlloyMetadata.new_simple("tenant")
        rotated = await sdk2.vector().rotate_vectors(
            vectors, metadata, "tenant"
        )  # unchanged tenant
        assert len(rotated.successes) == 1
        assert len(rotated.failures) == 0
        # Now that it's rotated, sometime in the future we have an SDK with only the new current
        vector_secrets3 = {
            "": VectorSecret(
                self.approximation_factor,
                # Switched current and in-rotation versus original sdk
                RotatableSecret(StandaloneSecret(1, Secret(self.key_bytes)), None),
            )
        }
        sdk3 = Standalone(
            StandaloneConfiguration(
                self.standard_secrets, self.deterministic_secrets, vector_secrets3
            )
        )
        decrypted = await sdk3.vector().decrypt(rotated.successes["vector"], metadata)
        assert decrypted.plaintext_vector == pytest.approx([1.0, 2.0, 3.0], rel=1e-5)

    @pytest.mark.asyncio
    async def test_encrypt_deterministic(self):
        field = PlaintextField(
            plaintext_field=b"My data", secret_path="", derivation_path=""
        )
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.deterministic().encrypt(field, metadata)
        expected = b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
        assert base64.b64encode(encrypted.encrypted_field) == expected

    @pytest.mark.asyncio
    async def test_generate_query_field_values_deterministic(self):
        field = PlaintextField(
            plaintext_field=b"My data", secret_path="", derivation_path=""
        )
        fields = {"foo": field}
        metadata = AlloyMetadata.new_simple("tenant")
        queries = await self.sdk.deterministic().generate_query_field_values(
            fields, metadata
        )
        expected = b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
        assert base64.b64encode(queries["foo"][0].encrypted_field) == expected

    @pytest.mark.asyncio
    async def test_roundtrip_standard(self):
        document = {"foo": b"My data"}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.standard().encrypt(document, metadata)
        assert len(encrypted.document["foo"]) == 40
        assert encrypted.document["foo"] != document["foo"]
        decrypted = await self.sdk.standard().decrypt(encrypted, metadata)
        assert decrypted == document

    @pytest.mark.asyncio
    async def test_roundtrip_standard_attached(self):
        document = b"My data"
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.standard_attached().encrypt(document, metadata)
        assert encrypted != document
        decrypted = await self.sdk.standard_attached().decrypt(encrypted, metadata)
        assert decrypted == document

    @pytest.mark.asyncio
    async def test_encrypt_with_existing_edek(self):
        document = {"foo": b"My data"}
        document2 = {"foo": b"My data2"}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.standard().encrypt(document, metadata)
        encrypted2 = await self.sdk.standard().encrypt_with_existing_edek(
            PlaintextDocumentWithEdek(edek=encrypted.edek, document=document2), metadata
        )
        assert encrypted.document["foo"] != encrypted2.document["foo"]
        assert encrypted.edek == encrypted2.edek
        decrypted = await self.sdk.standard().decrypt(encrypted2, metadata)
        assert decrypted == document2

    @pytest.mark.asyncio
    async def test_deterministic_batch_roundtrip(self):
        plaintext_input = b"foobar"
        field = PlaintextField(
            plaintext_field=plaintext_input,
            secret_path="",
            derivation_path="",
        )
        bad_field = PlaintextField(
            plaintext_field=plaintext_input,
            secret_path="bad_path",
            derivation_path="bad_path",
        )
        fields = {"doc": field, "bad_doc": bad_field}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.deterministic().encrypt_batch(fields, metadata)
        assert len(encrypted.successes) == 1
        assert len(encrypted.failures) == 1
        assert (
            encrypted.failures["bad_doc"].msg  # type: ignore
            == "Provided secret path `bad_path` does not exist in the deterministic configuration."
        )
        decrypted = await self.sdk.deterministic().decrypt_batch(
            encrypted.successes, metadata
        )
        assert len(decrypted.successes) == 1
        assert len(decrypted.failures) == 0
        assert decrypted.successes["doc"].plaintext_field == plaintext_input

    @pytest.mark.asyncio
    async def test_decrypt_deterministic_metadata(self):
        field = EncryptedField(
            encrypted_field=base64.b64decode(
                b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
            ),
            secret_path="",
            derivation_path="",
        )
        metadata = AlloyMetadata.new_simple("tenant")
        decrypted = await self.sdk.deterministic().decrypt(field, metadata)
        expected = b"My data"
        assert decrypted.plaintext_field == expected

    @pytest.mark.asyncio
    async def test_rotate_deterministic_different_tenant(self):
        field = EncryptedField(
            encrypted_field=base64.b64decode(
                b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
            ),
            secret_path="",
            derivation_path="",
        )
        fields = {"doc": field}
        metadata = AlloyMetadata.new_simple("tenant")
        rotated = await self.sdk.deterministic().rotate_fields(
            fields, metadata, "tenant2"
        )
        assert len(rotated.successes) == 1
        assert len(rotated.failures) == 0
        new_metadata = AlloyMetadata.new_simple("tenant2")
        decrypted = await self.sdk.deterministic().decrypt(
            rotated.successes["doc"], new_metadata
        )
        expected = b"My data"
        assert decrypted.plaintext_field == expected

    @pytest.mark.asyncio
    async def test_rotate_deterministic_different_key(self):
        deterministic_secrets2 = {
            "": RotatableSecret(
                # Switched current and in-rotation versus original sdk
                StandaloneSecret(1, Secret(self.key_bytes2)),
                StandaloneSecret(2, Secret(self.key_bytes)),
            )
        }
        sdk2 = Standalone(
            StandaloneConfiguration(
                self.standard_secrets, deterministic_secrets2, self.vector_secrets
            )
        )
        field = EncryptedField(
            encrypted_field=base64.b64decode(
                b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
            ),
            secret_path="",
            derivation_path="",
        )
        fields = {"doc": field}
        metadata = AlloyMetadata.new_simple("tenant")
        rotated = await sdk2.deterministic().rotate_fields(
            fields, metadata, "tenant"
        )  # unchanged tenant
        assert len(rotated.successes) == 1
        assert len(rotated.failures) == 0
        # Now that it's rotated, sometime in the future we have an SDK with only the new current
        deterministic_secrets3 = {
            "": RotatableSecret(
                StandaloneSecret(1, Secret(self.key_bytes2)),
                None,
            )
        }
        sdk3 = Standalone(
            StandaloneConfiguration(
                self.standard_secrets, deterministic_secrets3, self.vector_secrets
            )
        )
        decrypted = await sdk3.deterministic().decrypt(
            rotated.successes["doc"], metadata
        )
        expected = b"My data"
        assert decrypted.plaintext_field == expected

    @pytest.mark.asyncio
    async def test_rotate_deterministic_failures(self):
        field = EncryptedField(
            encrypted_field=base64.b64decode(
                b"AAAAAoAA4hdzU2eh2aeCoUSq6NQiWYczhmQQNak="
            ),
            secret_path="wrong_path",
            derivation_path="wrong_path",
        )
        fields = {"doc": field}
        metadata = AlloyMetadata.new_simple("tenant")
        rotated = await self.sdk.deterministic().rotate_fields(
            fields, metadata, "tenant2"
        )
        assert len(rotated.successes) == 0
        assert len(rotated.failures) == 1
        assert (
            "Provided secret path `wrong_path` does not exist"
            in rotated.failures["doc"].msg  # type: ignore
        )

    @pytest.mark.skip(reason="need seeded client")
    @pytest.mark.asyncio
    async def test_encrypt_probabilistic_metadata(self):
        # seeded_sdk = IroncoreAlloyStandalone.new_test_seeded(
        #     self.key, self.approximation_factor, 123
        # )
        document = {"foo": b"My data"}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.standard().encrypt(document, metadata)
        expected = b"AElST047XW9umwlxe053wEV18Vn5REOO4xh1s+2PAJk9E/h2lSug0A=="
        print(base64.b64encode(encrypted.edek))
        print(base64.b64encode(encrypted.document["foo"]))
        assert len(encrypted.document["foo"]) == 40
        assert base64.b64encode(encrypted.document["foo"]) == expected

    @pytest.mark.asyncio
    async def test_consecutive_encrypt_standard_calls_different(self):
        document = {"foo": b"My data"}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted1 = await self.sdk.standard().encrypt(document, metadata)
        encrypted2 = await self.sdk.standard().encrypt(document, metadata)
        assert encrypted1.document["foo"] != encrypted2.document["foo"]

    @pytest.mark.asyncio
    async def test_decrypt_standard(self):
        ciphertext = {
            "foo": base64.b64decode(
                b"AElST07h7vW2rFal+zxZTznlxWv9Cght683STVYhaOXuHUE/F2ib0A=="
            )
        }
        metadata = AlloyMetadata.new_simple("tenant")
        document = EncryptedDocument(
            edek=base64.b64decode(
                b"AAAACoIACiQKIN4xdr7dvQBFroI6JDHyeDktSkAAOsKEgv9P/VtM+qVEEAESSBJGGkQKDOpZqVwXBoutX3E0jRIwHp364nCATXkfLhIeYpkHLqLa0lzM3J/y9ZYEAlEPFu/VF4ErphypZRe/ReSbm9ZFGgIxMA=="
            ),
            document=ciphertext,
        )
        decrypted = await self.sdk.standard().decrypt(document, metadata)
        assert decrypted["foo"] == b"My data"

    @pytest.mark.asyncio
    async def test_rekey_edeks_standard(self):
        document = {"foo": b"My data"}
        metadata = AlloyMetadata.new_simple("tenant")
        encrypted = await self.sdk.standard().encrypt(document, metadata)
        edeks = {"edek": encrypted.edek}
        new_tenant = "tenant2"
        rekeyed = await self.sdk.standard().rekey_edeks(edeks, metadata, new_tenant)
        assert len(rekeyed.failures) == 0
        assert rekeyed.successes["edek"] != encrypted.edek
        remade_document = EncryptedDocument(
            edek=rekeyed.successes["edek"], document=encrypted.document
        )
        new_metadata = AlloyMetadata.new_simple(new_tenant)
        decrypted = await self.sdk.standard().decrypt(remade_document, new_metadata)
        assert decrypted["foo"] == b"My data"

    @pytest.mark.asyncio
    async def test_decrypt_wrong_type(self):
        with pytest.raises(AlloyError.InvalidInput):
            ciphertext = {
                "foo": base64.b64decode(b"AAAAAAAAMs7OVNXWuwUuW1DJVxlTbqoRTFdWKzM=")
            }
            encrypted = EncryptedDocument(
                edek=base64.b64decode(
                    b"CiQKIJpn4wkFfEtcl3DurQ/wLGcWK+Fr0nDEJ86y+faCyiDrEAESRBJCGkAKDO+cie3HH99isWQqoRIwUX9m/SzbhApKnZynLtX2ZDFTQXt5+Mol3qCQby5DfwqqQ8D/HdmFsmwpia5XqQHk"
                ),
                document=ciphertext,
            )
            metadata = AlloyMetadata.new_simple("tenant")
            await self.sdk.standard().decrypt(encrypted, metadata)

    @pytest.mark.asyncio
    async def test_error_handling(self):
        with pytest.raises(AlloyError.InvalidConfiguration) as secret_error:
            standard_secrets = StandardSecrets(None, [])
            deterministic_secrets = {}
            vector_secrets = {
                "": VectorSecret(
                    self.approximation_factor,
                    RotatableSecret(
                        StandaloneSecret(2, Secret(b"deadbeef")),
                        StandaloneSecret(1, Secret(b"key_bytes")),
                    ),
                )
            }
            config = StandaloneConfiguration(
                standard_secrets, deterministic_secrets, vector_secrets
            )
            bad_sdk = Standalone(config)

            metadata = AlloyMetadata.new_simple("tenant")
            await bad_sdk.vector().encrypt(
                PlaintextVector(
                    plaintext_vector=[1, 2, 4], secret_path="", derivation_path=""
                ),
                metadata,
            )
        assert "at least 32 cryptographically" in str(secret_error)

    def test_double_library_load(self):
        import ironcore_alloy
        import importlib

        importlib.reload(ironcore_alloy)
        # if it can still create a Standalone object through the FFI we'll assume it's still good after the reload
        sdk = Standalone(self.config)

    @pytest.mark.skip(reason="Integration test. Unskip as desired")
    @pytest.mark.asyncio
    async def test_unknown_tenant(self):
        with pytest.raises(AlloyError.TspError) as tsp_error:
            metadata = AlloyMetadata.new_simple("fake_tenant")
            await self.integration_sdk.vector().encrypt(
                PlaintextVector(
                    plaintext_vector=[1, 2, 4], secret_path="", derivation_path=""
                ),
                metadata,
            )
        assert "Tenant either doesn't exist" in tsp_error.value.msg

    @pytest.mark.asyncio
    async def test_bad_request(self):
        with pytest.raises(AlloyError.RequestError) as request_error:
            bad_integration_sdk = SaasShield(
                SaasShieldConfiguration(
                    "http://bad-url", "0WUaXesNgbTAuLwn", False, 1.1
                )
            )
            metadata = AlloyMetadata.new_simple("fake_tenant")
            await bad_integration_sdk.vector().encrypt(
                PlaintextVector(
                    plaintext_vector=[1, 2, 4], secret_path="", derivation_path=""
                ),
                metadata,
            )
        assert "error sending request for url" in str(request_error.value.msg)
