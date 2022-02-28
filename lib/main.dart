import 'package:bloc/bloc.dart';
import 'package:firebase_auth_bloc/api_keys.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/widgets.dart';

import 'app/app.dart';
import 'app/bloc_observer.dart';
import 'auth_repository/auth_repository.dart';

const webFirebaseOption = FirebaseOptions(
    apiKey: kApiKey,
    appId: kAppId,
    messagingSenderId: kMessagingSenderId,
    projectId: kProjectId,
    authDomain: null,
    storageBucket: null);

Future<void> main() {
  return BlocOverrides.runZoned(
    () async {
      WidgetsFlutterBinding.ensureInitialized();
      // For web initialize Firebase with web options
      // await Firebase.initializeApp(options: webFirebaseOption);
      await Firebase.initializeApp();
      final authenticationRepository = AuthenticationRepository();
      await authenticationRepository.user.first;
      runApp(App(authenticationRepository: authenticationRepository));
    },
    blocObserver: AppBlocObserver(),
  );
}
