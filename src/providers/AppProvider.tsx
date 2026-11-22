import { NavigationContainer } from "@react-navigation/native";
import { StatusBar } from "expo-status-bar";
import type { ReactNode } from "react";
import { SafeAreaProvider } from "react-native-safe-area-context";

export function AppProvider({ children }: { children: ReactNode }) {
  return (
    <SafeAreaProvider>
      <NavigationContainer>
        {children}
        <StatusBar style="auto" />
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
