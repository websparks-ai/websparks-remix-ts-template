import type { MetaFunction } from "@remix-run/node";
import { ClientOnly } from "remix-utils/client-only";
import FingerprintDemo from "~/components/FingerprintDemo";

export const meta: MetaFunction = () => {
  return [
    { title: "Advanced Device Fingerprinting Demo" },
    { name: "description", content: "Comprehensive fraud detection system combining device fingerprinting, incognito detection, IP analysis, and behavior tracking." },
  ];
};

export default function Index() {
  return (
    <ClientOnly fallback={
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading fingerprinting system...</p>
        </div>
      </div>
    }>
      {() => <FingerprintDemo />}
    </ClientOnly>
  );
}