import '../wallet_sdk/wallet_sdk.dart';
import 'config_service.dart';

class AttestationService {
  static String get attestationURL => ConfigService.config.attestationURL;

  static Future<void> issueAttestationVC() async {
    if (attestationURL.isEmpty) {
      _attestationVC = null;
      return;
    }

    _attestationVC = await WalletSDK()
        .getAttestationVC(attestationURL: attestationURL, attestationPayload: ConfigService.config.attestationPayload);
  }

  static Future<String?> returnAttestationVCIfEnabled() async {
    return _attestationVC;
  }

  static String? _attestationVC;
}