package io.venas;

import static java.lang.System.out;
import static org.apache.commons.codec.binary.Hex.decodeHex;
import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.apache.commons.lang3.StringUtils.repeat;
import static org.apache.commons.lang3.StringUtils.substring;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import com.google.common.base.Joiner;

public class ECKeyUtil {

	public static void main1(String[] args) throws Exception {

		{
			String publicKeyHex = "047c0b8e13739447ff0b1ace9138944ed1e29077acbd4662f02bb3142423edefd1ccee88f9d5cf13fd073cb234acd15299d128b338f2ba0b601607a49adfbd2088";
			out.println("publicKey:" + publicKeyHex);
			String keyId = publicKeyHexToKeyId(publicKeyHex);
			out.println("keyId:" + keyId);
			out.println("address:" + publicKeyHexToAddress(publicKeyHex));
		}

		{
			String publicKeyHex = "045ba64f393431e6f2bc10c285f88f815ee700d99fd5ad3564a3403045682e39ce6d0643c9e10469982346a640416f33ab05a8912f7694f313d9f41104d938dcb4";
			out.println("publicKey:" + publicKeyHex);
			String keyId = publicKeyHexToKeyId(publicKeyHex);
			out.println("keyId:" + keyId);
			out.println("address:" + publicKeyHexToAddress(publicKeyHex));
		}

		{
			String publicKeyHex = "04607114879724c26222a3acafe3dc943fb0d75dd4e48e406656dcdef7e0777288311887b8e388017e2ae643946cc47662a257ae96b0b54f26a5b86f333081f5d9";
			out.println("publicKey:" + publicKeyHex);
			String keyId = publicKeyHexToKeyId(publicKeyHex);
			out.println("keyId:" + keyId);
			out.println("address:" + publicKeyHexToAddress(publicKeyHex));
		}

		{
			String publicKeyHex = "045de13860f25d602fe8738c2cd8fe63933208cbaee3f766e6c7c152cc6c420d1545c6d63a1c775b1f7abf826760ab34c0183b59eaa95b6afeea2db028fd914da6";
			out.println("publicKey:" + publicKeyHex);
			String keyId = publicKeyHexToKeyId(publicKeyHex);
			out.println("keyId:" + keyId);
			out.println("address:" + publicKeyHexToAddress(publicKeyHex));
		}

		String privateKeyHex1 = "7a339d138d54fb599786552bf675b7aab5b78fe168dd99f4450f909984544782";
		ECPrivateKeyParameters privateKey1 = privateKeyHexToPrivateKey(privateKeyHex1);
		String privateKeyStr1 = privateKeyToPrivateKeyHex(privateKey1);
		out.println("privateKeyHex1:" + privateKeyHex1);
		out.println("privateKeyStr1:" + privateKeyStr1);
		{
			String publicKeyHex2 = "045ba64f393431e6f2bc10c285f88f815ee700d99fd5ad3564a3403045682e39ce6d0643c9e10469982346a640416f33ab05a8912f7694f313d9f41104d938dcb4";
			ECPublicKeyParameters publicKey2 = publicKeyHexToPublicKey(publicKeyHex2);
			String publicKeyStr2 = publicKeyToPublicKeyHex(publicKey2);
			out.println("publicKeyHex2:" + publicKeyHex2);
			out.println("publicKeyStr2:" + publicKeyStr2);
		}

		{
			ECPublicKeyParameters publicKey3 = privateKeyToPublicKey(privateKey1);
			String publicKeyStr3 = publicKeyToPublicKeyHex(publicKey3);
			out.println("publicKeyStr3:" + publicKeyStr3);
			byte[] input = "LOGIN1156326149442837646".getBytes();

			byte[] signature = sign(privateKey1, input);
			out.println("sign1:" + encodeHexString(signature));

			String sigStr = "3045022050b52706e1a3027336cb1db9de489d98248f1ccfeb5bc369ff439020035052e5022100b40b05d29ac9bdedd95608863b5c5c0b12aa54e1cfd5ab82a09cfcd7de23b2ae";
			signature = decodeHex(sigStr);
			out.println("sign2:" + encodeHexString(signature));

			boolean res2 = verify(publicKey3, input, signature);
			out.println("verify2:" + res2);
		}

		{
			// 测试随机秘钥生成
			AsymmetricCipherKeyPair keyPair = generateKeyPair();
			ECPrivateKeyParameters privG = (ECPrivateKeyParameters) keyPair.getPrivate();
			String privateKeyHex = privateKeyToPrivateKeyHex(privG);
			out.println("privateKeyHex:" + privateKeyHex);
			ECPublicKeyParameters pubG = (ECPublicKeyParameters) keyPair.getPublic();
			String publicKeyHex = publicKeyToPublicKeyHex(pubG);
			out.println("publicKeyHex:" + publicKeyHex);
			out.println("keyId:" + publicKeyHexToKeyId(publicKeyHex));
			out.println("address:" + publicKeyHexToAddress(publicKeyHex));
		}
		{

			String seed = Joiner.on(" ").join(createMnemonic());

//			String seed = "potato expire change year february curious inject barely mix wait cry verb theory sadness refuse";
			String privateKeyHex = seedToPublicKeyHex(seed);
			ECPrivateKeyParameters privateKey = privateKeyHexToPrivateKey(privateKeyHex);
			ECPublicKeyParameters publicKey = privateKeyToPublicKey(privateKey);
			String publicKeyHex = publicKeyToPublicKeyHex(publicKey);
			String address = publicKeyHexToAddress(publicKeyHex);
			String KeyID = publicKeyHexToKeyId(publicKeyHex);
			out.println("seed:" + seed);
			out.println("privateKeyHex:" + privateKeyHex);
			out.println("publicKeyHex:" + publicKeyHex);
			out.println("KeyID:" + KeyID);
			out.println("address:" + address);
		}
	}

	/**
	 * publicKey公钥对象转成公钥字符串publicKeyHex
	 * 
	 * @param publicKey
	 * @return publicKeyHex
	 */
	public static String publicKeyToPublicKeyHex(ECPublicKeyParameters publicKey) {
		return encodeHexString(publicKey.getQ().getEncoded(false));
	}

	/**
	 * 根据助记词字符串生成 私钥字符串privateKeyHex
	 * 
	 * @param seed
	 * @return
	 * @throws Exception
	 */
	public static String seedToPublicKeyHex(String seed) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] cipherBytes = messageDigest.digest(seed.getBytes());
		String seedHex = encodeHexString(cipherBytes);
		return seedHex;
	}

	/**
	 * privateKey私钥对象转成私钥字符串privateKeyHex
	 * 
	 * @param privateKey
	 * @return privateKeyHex
	 */
	public static String privateKeyToPrivateKeyHex(ECPrivateKeyParameters privateKey) {
		return privateKey.getD().toString(16);
	}

	/**
	 * privateKey私钥对象转成公钥对象publicKey
	 * 
	 * @param privateKey
	 * @return publicKey
	 */
	public static ECPublicKeyParameters privateKeyToPublicKey(ECPrivateKeyParameters privateKey) {
		X9ECParameters curveParams = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
		ECPoint q = domainParams.getG().multiply(privateKey.getD());
		return new ECPublicKeyParameters(q, domainParams);
	}

	/**
	 * privateKeyHex私钥字符串转成私钥对象privateKey
	 * 
	 * @param privateKeyHex
	 * @return privateKey
	 */
	public static ECPrivateKeyParameters privateKeyHexToPrivateKey(String privateKeyHex) {
		X9ECParameters curveParams = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
		BigInteger keyInt = new BigInteger(privateKeyHex, 16);
		return new ECPrivateKeyParameters(keyInt, domainParams);
	}

	/**
	 * publicKeyHex公钥字符串转成keyId
	 * 
	 * @param publicKeyHex
	 * @return keyId
	 * @throws Exception
	 */
	public static String publicKeyHexToKeyId(String publicKeyHex) throws Exception {
		String pub = substring(publicKeyHex, 2);
		byte[] pubhex = decodeHex(pub);
		byte[] sha256 = getSHA(pubhex, "SHA-256");
		byte[] sha512 = getSHA(sha256, "SHA-512");
		long crc64 = crc64(sha512);
		BigDecimal crc64b = longParseUnsigned(crc64);
		String crc64str = crc64b.toString();
//		out.println("crc64str:" + crc64str);
		crc64str = repeat("0", 20 - crc64str.length()) + crc64str;
		int addrChecksum = checkSum(crc64str.getBytes());
//		out.println(addrChecksum);
		BigDecimal keyIdb = crc64b.subtract(crc64b.remainder(new BigDecimal(10))).add(new BigDecimal(addrChecksum));
//		out.println("keyIdb:"+keyIdb);
//		long keyId = crc64 - (crc64 % 10) + addrChecksum;
//		BigDecimal keyIdb = longParseUnsigned(keyId);
		return keyIdb.toString();
	}

	public static String publicKeyHexToAddress(String publicKeyHex) throws Exception {
		String keyId = publicKeyHexToKeyId(publicKeyHex);
		String keyIdstr = repeat("0", 20 - keyId.length()) + keyId;
		char[] val = keyIdstr.toCharArray();
		String address = "";
		for (int i = 0; i < val.length; i++) {
			if (i % 4 == 0 && i > 0) {
				address += "-";
			}
			address += val[i];
		}
		return address;
	}

	/**
	 * publicKeyHex公钥字符串转成公钥对象publicKey
	 * 
	 * @param publicKeyHex
	 * @return publicKey
	 * @throws Exception
	 */
	public static ECPublicKeyParameters publicKeyHexToPublicKey(String publicKeyHex) throws Exception {
		X9ECParameters curveParams = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
		ECPoint point = domainParams.getCurve().decodePoint(decodeHex(publicKeyHex));
		return new ECPublicKeyParameters(point, domainParams);
	}

	/**
	 * secp256r1 (椭圆曲线密钥)生成秘钥对 privateKey / publicKey
	 * 
	 * <pre>
	 * AsymmetricCipherKeyPair keyPair = generateKeyPair();
	 * ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
	 * ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
	 * </pre>
	 */
	public static AsymmetricCipherKeyPair generateKeyPair() {
		X9ECParameters curveParams = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH(), curveParams.getSeed());
		ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(keyGenParams);
		return generator.generateKeyPair();
	}

	/**
	 * 签名数据
	 * 
	 * @param private1
	 * @param data
	 * @return
	 */
	public static byte[] sign(ECPrivateKeyParameters private1, byte[] data) {
		Digest digest = new SHA256Digest();
		DSAKCalculator calculator = new HMacDSAKCalculator(digest);
		DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(calculator), digest);
		signer.init(true, private1);
		signer.update(data, 0, data.length);
		return signer.generateSignature();
	}

	/**
	 * 验证签名
	 * 
	 * @param publicKey
	 * @param data
	 * @param signature
	 * @return
	 */
	public static boolean verify(ECPublicKeyParameters publicKey, byte[] data, byte[] signature) {
		Digest digest = new SHA256Digest();
		DSAKCalculator calculator = new HMacDSAKCalculator(digest);
		DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(calculator), digest);
		signer.init(false, publicKey);
		signer.update(data, 0, data.length);
		return signer.verifySignature(signature);
	}

	/**
	 * SHA-256/ SHA-512
	 * 
	 * @param input
	 * @param algorithm
	 * @return
	 */
	public static byte[] getSHA(byte[] input, String algorithm) {
		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance(algorithm);
			messageDigest.update(input);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return messageDigest.digest();
	}

	private static int checkSum(byte[] val) {
		int one = 0, two = 0;
		for (int i = 0; i < val.length - 1; i++) {
			byte ch = val[i];
			int digit = (ch - '0');
			if ((i & 1) == 1) {
				one += digit;
			} else {
				two += digit;
			}
		}
		int checksum = (two + 3 * one) % 10;
		if (checksum > 0) {
			checksum = 10 - checksum;
		}
		return checksum;
	}

	/*
	 * ECMA: 0x42F0E1EBA9EA3693 / 0xC96C5795D7870F42 / 0xA17870F5D4F51B49
	 */
	private static final long POLY64 = 0xC96C5795D7870F42L;
	private static final long[] CRC64_TABLE;

	static {
		CRC64_TABLE = new long[0x100];
		for (int i = 0; i < 0x100; i++) {
			long crc = i;
			for (int j = 0; j < 8; j++) {
				if ((crc & 1) == 1) {
					crc = (crc >>> 1) ^ POLY64;
				} else {
					crc = (crc >>> 1);
				}
			}
			CRC64_TABLE[i] = crc;
		}
	}

	/**
	 * CRC64 即循环冗余校验
	 * 
	 * @param data
	 * @return crc64 long
	 */
	public static long crc64(final byte[] data) {
		long checksum = ~0;
		for (int i = 0; i < data.length; i++) {
			final int lookupidx = ((int) checksum ^ data[i]) & 0xff;
			checksum = CRC64_TABLE[lookupidx] ^ (checksum >>> 8);
		}
		return ~checksum;
	}

	private static boolean[] bytesToBits(byte[] data) {
		boolean[] bits = new boolean[data.length * 8];
		for (int i = 0; i < data.length; ++i)
			for (int j = 0; j < 8; ++j)
				bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
		return bits;
	}

	private static final String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";
	public static String[] WORD_LIST = new String[] { "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
			"achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice",
			"aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley",
			"allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
			"animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
			"arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
			"assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
			"aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
			"barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
			"benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
			"bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
			"bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
			"broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
			"butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
			"canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
			"cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter",
			"charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn",
			"cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip",
			"clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column",
			"combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy",
			"coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater",
			"crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush",
			"cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger",
			"daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree",
			"delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair",
			"destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
			"dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog",
			"doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink",
			"drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
			"echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
			"embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
			"enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
			"erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
			"execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
			"fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
			"fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film",
			"filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
			"flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune",
			"forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun",
			"funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge",
			"gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide",
			"glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
			"grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit",
			"hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height",
			"hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood",
			"hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt",
			"husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse",
			"inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner",
			"innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
			"item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk",
			"just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
			"lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader",
			"leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
			"license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely",
			"long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail",
			"main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master",
			"match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention",
			"menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle",
			"mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
			"mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself",
			"mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network",
			"neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear",
			"number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil",
			"okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary",
			"organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle",
			"page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern",
			"pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo",
			"phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate",
			"play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
			"potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
			"prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public",
			"pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter",
			"question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare",
			"rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse",
			"region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
			"report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon",
			"rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof",
			"rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
			"salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school",
			"science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment",
			"select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff",
			"shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege",
			"sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt",
			"skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
			"sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
			"source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor",
			"spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
			"steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle",
			"student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super",
			"supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing",
			"switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team",
			"tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
			"thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet",
			"token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower",
			"town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim",
			"trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty",
			"twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique",
			"unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
			"useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture",
			"venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa",
			"visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm",
			"warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale",
			"what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom",
			"wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
			"yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo" };

	public static List<String> createMnemonic() throws Exception {
		ArrayList<String> wordList = new ArrayList<>(2048);
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		for (String word : WORD_LIST) {
			md.update(word.getBytes());
			wordList.add(word);
		}

		if (wordList.size() != 2048)
			throw new IllegalArgumentException("input stream did not contain 2048 words");

		// If a wordListDigest is supplied check to make sure it matches.

		byte[] digest = md.digest();
		String hexdigest = encodeHexString(digest); // BaseEncoding.base16().lowerCase().encode(digest);

		out.println("wordlist digest mismatch\n" + hexdigest.toLowerCase().equals(BIP39_ENGLISH_SHA256));

		SecureRandom random = new SecureRandom();

		byte[] entropy = new byte[160 / 8];
		random.nextBytes(entropy);

		byte[] hash = getSHA(entropy, "SHA-256");// Sha256Hash.hash(entropy);

		boolean[] hashBits = bytesToBits(hash);

		boolean[] entropyBits = bytesToBits(entropy);
		int checksumLengthBits = entropyBits.length / 32;

		// We append these bits to the end of the initial entropy.
		boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
		System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
		System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);

		// Next we take these concatenated bits and split them into
		// groups of 11 bits. Each group encodes number from 0-2047
		// which is a position in a wordlist. We convert numbers into
		// words and use joined words as mnemonic sentence.

		ArrayList<String> words = new ArrayList<>();
		int nwords = concatBits.length / 11;
		for (int i = 0; i < nwords; ++i) {
			int index = 0;
			for (int j = 0; j < 11; ++j) {
				index <<= 1;
				if (concatBits[(i * 11) + j])
					index |= 0x1;
			}
			words.add(wordList.get(index));
		}

		return words;
	}

	/**
	 * long转成无符号数<br>
	 * java中long类型转换成无符号数
	 */

	public static final BigDecimal longParseUnsigned(long value) {
		if (value >= 0)
			return new BigDecimal(value);
		long lowValue = value & 0x7fffffffffffffffL;
		return BigDecimal.valueOf(lowValue).add(BigDecimal.valueOf(Long.MAX_VALUE)).add(BigDecimal.valueOf(1));
	}

	/**
	 * long转成有符号数<br>
	 * java中无符号数转换成有符号数
	 * 
	 * @param str
	 * @return
	 */
	public static final long parseUnsignedLong(String str) {
		BigDecimal data = new BigDecimal(str);
		long l = data.subtract(new BigDecimal(Long.MAX_VALUE)).subtract(BigDecimal.valueOf(1)).longValue();
		return l | Long.MIN_VALUE;
	}

	/**
	 * 合并byte数组
	 * 
	 * @param values
	 * @return
	 */
	public static byte[] byteMergerAll(byte[]... values) {
		int length_byte = 0;
		for (int i = 0; i < values.length; i++) {
			length_byte += values[i].length;
		}
		byte[] all_byte = new byte[length_byte];
		int countLength = 0;
		for (int i = 0; i < values.length; i++) {
			byte[] b = values[i];
			System.arraycopy(b, 0, all_byte, countLength, b.length);
			countLength += b.length;
		}
		return all_byte;
	}

	public static String getPrintHex(byte[] data, int offset, int limit) {
		StringBuffer sb = new StringBuffer();
		for (int i = offset; i < offset + limit; i++) {
			sb.append(String.format("%02x", data[i]));
			sb.append(",");
		}
		return sb.toString();
	}

	public static String getPrintHex(byte[] data) {

		return getPrintHex(data, 0, data.length);
	}

	public static byte[] to16(String str, int radix) {
		String[] bs = str.split(",");
		byte[] buf = new byte[bs.length];
		for (int i = 0; i < bs.length; i++) {
			buf[i] = (byte) (Integer.parseInt(bs[i], radix) & 0xff);
		}
		return buf;
	}

	public static byte[] intToBigEndianBytes(int i) {
		byte[] b = new byte[4];
		b[0] = (byte) ((0xff000000 & i) >> 24);
		b[1] = (byte) ((0x00ff0000 & i) >> 16);
		b[2] = (byte) ((0x0000ff00 & i) >> 8);
		b[3] = (byte) (0x000000ff & i);
		return b;
	}

	public static byte[] intToLittleEndianBytes(int i) {
		byte[] b = new byte[4];
		b[0] = (byte) (0x000000ff & i);
		b[1] = (byte) ((0x0000ff00 & i) >> 8);
		b[2] = (byte) ((0x00ff0000 & i) >> 16);
		b[3] = (byte) (i >> 24);
		return b;
	}

	public static int bigEndianBytesToInt(byte[] b) {
		return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
	}

	public static int littleEndianBytesToInt(byte[] b) {
		return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0];
	}

	// EncodeLength encodes int64 number to []byte. If it is less than 128 then it
	// returns []byte{length}.
	// Otherwise, it returns (0x80 | len of int64) + int64 as BigEndian []byte
	//
	// 67 => 0x43
	// 1024 => 0x820400
	// 1000000 => 0x830f4240
	//
	public static byte[] EncodeLength(int length) {
		if (length >= 0 && length <= 127) {

			return new byte[] { (byte) length };
		}

//		byte[] b = PutUint64(length);
		byte[] b = intToBigEndianBytes(length);
//		System.out.println("byte length" + getPrintHex(b));
		int i = 0;
		for (; b[i] == 0 && i < b.length; i++) {
		}

		byte[] ddata3 = subBytes(b, i, b.length - i);
//		System.arraycopy(b, 0, ddata3, 0, b.length);

//		System.out.println(i);
		byte[] buf = new byte[1];
		buf[0] = (byte) (0x80 | (byte) (b.length - i));

		return byteMergerAll(buf, ddata3);
	}

	public static byte[] subBytes(byte[] src, int begin, int count) {
		byte[] bs = new byte[count];
		for (int i = begin; i < begin + count; i++)
			bs[i - begin] = src[i];
		return bs;
	}

	public static byte[] PutUint64(int v) {
		byte[] b = new byte[8];
		b[0] = (byte) (v >> 56);
		b[1] = (byte) (v >> 48);
		b[2] = (byte) (v >> 40);
		b[3] = (byte) (v >> 32);
		b[4] = (byte) (v >> 24);
		b[5] = (byte) (v >> 16);
		b[6] = (byte) (v >> 8);
		b[7] = (byte) (v);
		return b;
	}

	public static void main(String[] args) {
//		{
//			byte[] data = PutUint64(1024);
//			System.out.println("PutUint64 " + getPrintHex(data));
//			byte[] data2 = PutUint64(231);
//			System.out.println("PutUint64 " + getPrintHex(data2));
//			byte[] data3 = PutUint64(1000000);
//			System.out.println("PutUint64 " + getPrintHex(data3));
//		}
//		{
//			byte[] data = intToBigEndianBytes(1024);
//			System.out.println("intToBigEndianBytes " + getPrintHex(data));
//			byte[] data2 = intToBigEndianBytes(231);
//			System.out.println("intToBigEndianBytes " + getPrintHex(data2));
//			byte[] data3 = intToBigEndianBytes(1000000);
//			System.out.println("intToBigEndianBytes " + getPrintHex(data3));
//		}
		{
			byte[] data0 = EncodeLength(373);
			System.out.println("EncodeLength " + getPrintHex(data0));
//			byte[] data = EncodeLength(1024);
//			System.out.println("EncodeLength " + getPrintHex(data));
//			byte[] data2 = EncodeLength(231);
//			System.out.println("EncodeLength " + getPrintHex(data2));
//			byte[] data3 = EncodeLength(1000000);
//			System.out.println("EncodeLength " + getPrintHex(data3));

		}
//		System.out.println(   0x80 | (byte) (9 - 7) ); 
	}

}