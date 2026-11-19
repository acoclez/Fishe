import { expect, it } from "vitest";
import { serviceName } from "./services";

it("names well-known ports per transport", () => {
  expect(serviceName("tcp", 443)).toBe("HTTPS");
  expect(serviceName("udp", 443)).toBe("QUIC");
  expect(serviceName("udp", 51820)).toBe("WireGuard");
  expect(serviceName("tcp", 51820)).toBeNull();
  expect(serviceName("icmp", 80)).toBeNull();
  expect(serviceName("other", 53)).toBeNull();
});
