import CryptoJS from "crypto-js";
import * as Random from "expo-random";
import RNFetchBlob, { FetchBlobResponse } from "react-native-blob-util";
import {
	EncryptionMethod,
	LoginResponse,
	TapoBasicInfo,
	TapoConstructor,
	TapoLED,
	TapoLEDConfig,
	TapoLEDStatus,
	TapoLensMask,
	TapoLensMaskStatus,
	TapoMediaEncrypt,
	TapoMediaEncryptStatus,
	TapoPresets,
	TapoPresetsData,
	TapoRotationStatus,
	TapoRotationStatusData,
	TapoSDCardData,
	TapoSDCardInfo,
	TapoTimeData,
	TapoTimezone,
	TapoTimezoneData,
	TapoVideoCapabilities,
	TapoVideoQualities,
} from "./types";
import { ERROR_CODES, MAX_LOGIN_RETRIES } from "./constants";

export class TapoCamera {
	private retryStok: boolean;
	private redactConfidentialInformation: boolean;
	private printDebugInformation: boolean;
	private passwordEncryptionMethod: string | null = null;
	private seq: number | null = null;
	private host: string;
	private controlPort: number;
	private lsk: Buffer | undefined = undefined;
	private cnonce: string | null = null;
	private ivb: Buffer | undefined = undefined;
	private klapTransport: any = null;
	private user: string;
	private stok: string | false = false;
	private childID: string | null;
	private reuseSession: boolean;
	private isSecureConnectionCached: boolean | null = true;
	private headers: Record<string, string> = {};
	private hashedPassword: string = "";
	private hashedSha256Password: string = "";
	private basicInfo: any;
	private deviceType: string = "";
	private presets: any;
	private rnFetchBlock: RNFetchBlob | null = null;
	private timeCorrection?: number;

	constructor({
		host,
		user,
		password,
		childID = null,
		reuseSession = true,
		printDebugInformation = false,
		controlPort = 443,
		retryStok = true,
		redactConfidentialInformation = false,
	}: TapoConstructor) {
		this.retryStok = retryStok;
		this.redactConfidentialInformation = redactConfidentialInformation;
		this.printDebugInformation = printDebugInformation;
		this.host = host;
		this.user = user;
		this.childID = childID;
		this.reuseSession = reuseSession;
		this.controlPort = controlPort ?? 443;

		this.headers = {
			Host: this.getControlHost(),
			Referer: `https://${this.getControlHost()}`,
			Accept: "application/json",
			"Accept-Encoding": "gzip, deflate",
			"User-Agent": "Tapo CameraClient Android",
			Connection: "close",
			requestByApp: "true",
			"Content-Type": "application/json; charset=UTF-8",
		};

		this.hashedPassword = CryptoJS.MD5(password)
			.toString(CryptoJS.enc.Hex)
			.toUpperCase();

		this.hashedSha256Password = CryptoJS.SHA256(password)
			.toString(CryptoJS.enc.Hex)
			.toUpperCase();

		this.rnFetchBlock = RNFetchBlob.config({ trusty: true });
	}

	async init() {
		this.basicInfo = await this.getBasicInfo();

		if ("type" in this.basicInfo) {
			this.deviceType = this.basicInfo["type"];
		} else if (this.basicInfo.device_info?.basic_info?.device_type) {
			this.deviceType = this.basicInfo.device_info.basic_info.device_type;
		} else {
			this.deviceType = "";
			throw new Error("Failed to detect device type.");
		}

		this.presets = this.isSupportingPresets();
		if (!this.presets) {
			this.presets = {};
		}
		return this;
	}

	private getControlHost(): string {
		return `${this.host}:${this.controlPort}`;
	}

	getBasicInfo(): Promise<TapoBasicInfo> {
		return this.executeFunction<TapoBasicInfo>("getDeviceInfo", {
			device_info: { name: ["basic_info"] },
		});
	}

	getDeviceType(): string {
		return this.deviceType;
	}

	private isSupportingPresets(): any {
		try {
			const presets = this.getPresets();
			return presets;
		} catch (error) {
			return false;
		}
	}

	private async executeFunction<T>(
		method: string,
		params: any,
		retry = false
	): Promise<T> {
		let data: any;

		if (method === "multipleRequest") {
			if (params !== null && params !== undefined) {
				data = (
					await this.performRequest({
						method: "multipleRequest",
						params: params,
					})
				).result.responses;
			} else {
				data = (
					await this.performRequest({
						method: "multipleRequest",
					})
				).result.responses;
			}
		} else {
			if (params !== null && params !== undefined) {
				data = (
					await this.performRequest({
						method: "multipleRequest",
						params: {
							requests: [{ method: method, params: params }],
						},
					})
				).result.responses[0];
			} else {
				data = (
					await this.performRequest({
						method: "multipleRequest",
						params: {
							requests: [{ method: method }],
						},
					})
				).result.responses[0];
			}
		}

		if (Array.isArray(data)) {
			return data as T;
		}

		if (
			"result" in data &&
			(!("error_code" in data) || data.error_code === 0)
		) {
			return data.result;
		} else if (
			"method" in data &&
			"error_code" in data &&
			data.error_code === 0
		) {
			return data;
		} else {
			if (
				"error_code" in data &&
				data.error_code === -64303 &&
				retry === false
			) {
				this.setCruise(false);
				return this.executeFunction(method, params, true);
			}

			const errMsg =
				"err_msg" in data
					? data.err_msg
					: this.getErrorMessage(data.error_code);

			throw new Error(`Error: ${errMsg}, Response: ${JSON.stringify(data)}`);
		}
	}

	private async request(
		method: "GET" | "POST" | "PUT" | "DELETE",
		url: string,
		header: Record<string, string> = {},
		data: any
	): Promise<FetchBlobResponse> {
		let fetchBlob = this.rnFetchBlock;

		if (!this.reuseSession) {
			fetchBlob = RNFetchBlob.config({ trusty: true });
		}

		if (this.printDebugInformation) {
			const redactedConfig = JSON.parse(JSON.stringify({ header, data })); // deep clone

			if (this.redactConfidentialInformation) {
				if (redactedConfig.data) {
					try {
						const parsedData =
							typeof redactedConfig.data === "string"
								? JSON.parse(redactedConfig.data)
								: redactedConfig.data;

						if (parsedData.params) {
							if (parsedData.params.password)
								parsedData.params.password = "REDACTED";
							if (parsedData.params.digest_passwd)
								parsedData.params.digest_passwd = "REDACTED";
							if (parsedData.params.cnonce)
								parsedData.params.cnonce = "REDACTED";
						}

						redactedConfig.data = parsedData;
					} catch (e) {
						// JSON parse failed, skip redaction
					}
				}

				if (redactedConfig.headers) {
					if (redactedConfig.headers["Tapo_tag"])
						redactedConfig.headers["Tapo_tag"] = "REDACTED";
					if (redactedConfig.headers["Host"])
						redactedConfig.headers["Host"] = "REDACTED";
					if (redactedConfig.headers["Referer"])
						redactedConfig.headers["Referer"] = "REDACTED";
				}
			}

			this.debugLog("New request:");
			this.debugLog(redactedConfig);
		}

		try {
			const response = await fetchBlob!.fetch(method, url, header, data);

			if (this.printDebugInformation) {
				this.debugLog(`${response.info().status}`);

				try {
					const loadJson =
						response.respInfo.respType === "text"
							? JSON.parse(response.json())
							: response.json();

					if (this.redactConfidentialInformation && loadJson.result) {
						if (loadJson.result.stok) loadJson.result.stok = "REDACTED";
						if (loadJson.result.data) {
							if (loadJson.result.data.key)
								loadJson.result.data.key = "REDACTED";
							if (loadJson.result.data.nonce)
								loadJson.result.data.nonce = "REDACTED";
							if (loadJson.result.data.device_confirm)
								loadJson.result.data.device_confirm = "REDACTED";
						}
					}

					this.debugLog(loadJson);
				} catch (err) {
					this.debugLog("Failed to load json: " + err);
				}
			}

			if (!this.reuseSession) {
				// Axios no necesita cerrar conexiones manualmente
			}

			return response;
		} catch (error: any) {
			this.debugLog(`Request error: ${error.message}`);
			throw error;
		}
	}

	setCruise(enabled: boolean, coord: "x" | "y" | false = false): any {
		if (coord !== false && coord !== "x" && coord !== "y") {
			throw new Error("Invalid coord parameter. Can be 'x' or 'y'.");
		}

		if (enabled && coord !== false) {
			return this.executeFunction("cruiseMove", {
				motor: { cruise: { coord } },
			});
		} else {
			return this.executeFunction("cruiseStop", {
				motor: { cruise_stop: {} },
			});
		}
	}

	async getPresets(): Promise<TapoPresets> {
		const data = await this.executeFunction<TapoPresetsData>(
			"getPresetConfig",
			{
				preset: { name: ["preset"] },
			}
		);

		this.presets = this.processPresetsResponse(data);
		return this.presets;
	}

	private processPresetsResponse(response: TapoPresetsData): TapoPresets {
		const result: Record<string, string> = {};
		const ids = response.preset.preset.id;
		const names = response.preset.preset.name;

		ids.forEach((id: string, index: number) => {
			result[id] = names[index];
		});

		return result;
	}

	private async performRequest(
		requestData: any,
		loginRetryCount = 0
	): Promise<any> {
		await this.executeAsyncExecutorJob(() => this.ensureAuthenticated());

		let authValid = true;
		const url = this.getHostURL();
		let fullRequest: any;
		let responseJSON: any;
		let res: FetchBlobResponse | null = null;

		if (this.childID) {
			fullRequest = {
				method: "multipleRequest",
				params: {
					requests: [
						{
							method: "controlChild",
							params: {
								childControl: {
									device_id: this.childID,
									request_data: requestData,
								},
							},
						},
					],
				},
			};
		} else {
			fullRequest = requestData;
		}

		if (this.seq !== null && (await this.isSecureConnection())) {
			const encrypted = this.encryptRequest(JSON.stringify(fullRequest));
			const base64Request = Buffer.from(encrypted).toString("base64");

			fullRequest = {
				method: "securePassthrough",
				params: {
					request: base64Request,
				},
			};

			this.headers["Seq"] = this.seq.toString();

			try {
				this.headers["Tapo_tag"] = this.getTag(fullRequest);
			} catch (err: any) {
				if (err.message === "Failure detecting hashing algorithm.") {
					authValid = false;
					this.debugLog(
						"Failure detecting hashing algorithm on getTag, reauthenticating."
					);
				} else {
					throw err;
				}
			}

			this.seq += 1;
		}

		res = await this.request(
			"POST",
			url,
			this.headers,
			JSON.stringify(fullRequest)
		);

		const responseData = res.data;

		if ((await this.isSecureConnection()) && responseData?.result?.response) {
			const encryptedResponse = Buffer.from(
				responseData.result.response,
				"base64"
			);

			try {
				const decrypted = this.decryptResponse(encryptedResponse);
				responseJSON = JSON.parse(decrypted);
			} catch (err: any) {
				if (
					err.message === "Padding is incorrect." ||
					err.message === "PKCS#7 padding is incorrect."
				) {
					this.debugLog(`${err.message} Reauthenticating.`);
					authValid = false;
				} else {
					throw err;
				}
			}
		} else {
			responseJSON = responseData;
		}

		if (!authValid) {
			const errorCode = responseJSON?.error_code;
			if (
				(!authValid || errorCode === -40401 || errorCode === -1) &&
				loginRetryCount < MAX_LOGIN_RETRIES
			) {
				await this.refreshStok();
				return this.performRequest(requestData, loginRetryCount + 1);
			} else {
				throw new Error(
					`Error: ${this.getErrorMessage(
						errorCode
					)}, Response: ${JSON.stringify(responseJSON)}`
				);
			}
		}

		// Clean up child device response
		if (this.childID) {
			const responses = responseJSON.result.responses.map((resp: any) => {
				if (resp.method === "controlChild") {
					return resp.result.response_data ?? resp.result;
				} else {
					return resp.result;
				}
			});

			responseJSON.result.responses = responses;
			return responses[0];
		} else {
			return responseJSON;
		}
	}

	private decryptAes128CbcBase64(
		encrypted: Buffer,
		keyBuffer: Buffer,
		ivBuffer: Buffer
	): string {
		const keyWordArray = CryptoJS.enc.Hex.parse(keyBuffer.toString("hex"));
		const ivWordArray = CryptoJS.enc.Hex.parse(ivBuffer.toString("hex"));
		const ciphertextWordArray = CryptoJS.enc.Base64.parse(
			encrypted.toString("base64")
		);

		const cipherParams = CryptoJS.lib.CipherParams.create({
			ciphertext: ciphertextWordArray,
		});

		const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWordArray, {
			iv: ivWordArray,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7,
		});

		return decrypted.toString(CryptoJS.enc.Utf8);
	}

	private decryptResponse(response: Buffer): string {
		if (!this.lsk || !this.ivb) return "";
		return this.decryptAes128CbcBase64(response, this.lsk, this.ivb);
	}

	private sha256HexUpper(input: string): string {
		return CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(input))
			.toString(CryptoJS.enc.Hex)
			.toUpperCase();
	}

	private getTag(request: any): string {
		const hash1 = this.sha256HexUpper(this.getHashedPassword() + this.cnonce);
		const payload = hash1 + JSON.stringify(request) + String(this.seq);
		const tag = this.sha256HexUpper(payload);
		return tag;
	}

	private encryptRequest(request: string): Buffer {
		if (!this.lsk || !this.ivb) {
			return Buffer.from("");
		}

		const keyHex = this.lsk.toString("hex");
		const ivHex = this.ivb.toString("hex");

		const key = CryptoJS.enc.Hex.parse(keyHex);
		const iv = CryptoJS.enc.Hex.parse(ivHex);
		const plaintext = CryptoJS.enc.Utf8.parse(request);

		const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
			iv,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7,
		});

		// Convertimos el resultado a Buffer (desde base64)
		return Buffer.from(encrypted.toString(), "base64");
	}

	private async sendKlapRequest(request: any, retry = 0): Promise<any> {
		try {
			if (!this.klapTransport) {
				await this.ensureAuthenticated();
			}

			const response = await this.klapTransport.send(JSON.stringify(request));
			return response;
		} catch (err: any) {
			const errorMessage = String(err);

			if (
				errorMessage.includes("Response status is 403, Request was") ||
				errorMessage.includes("Response status is 400, Request was") ||
				errorMessage.includes("Server disconnected")
			) {
				throw new Error("Tapo NodeJS KLAP Error #6: " + errorMessage);
			}

			this.debugLog("Retrying request... Error: " + errorMessage);

			if (retry < 5) {
				await this.ensureAuthenticated();
				return this.sendKlapRequest(request, retry + 1);
			} else {
				throw new Error("Tapo NodeJS KLAP Error #1: " + errorMessage);
			}
		} finally {
			if (
				this.klapTransport &&
				typeof this.klapTransport.close === "function"
			) {
				await this.klapTransport.close();
			}
		}
	}

	private getErrorMessage(errorCode: number | string): string {
		const code = String(errorCode);
		if (code in ERROR_CODES) {
			return ERROR_CODES[code];
		} else {
			return code;
		}
	}

	private getHostURL(): string {
		return `https://${this.getControlHost()}/stok=${this.stok}/ds`;
	}

	private async executeAsyncExecutorJob<T>(
		job: (...args: any[]) => Promise<T>,
		...args: any[]
	): Promise<T> {
		return await job(...args);
	}

	private debugLog(msg: string): void {
		console.log(msg);
	}

	private async isSecureConnection(): Promise<boolean> {
		if (this.isSecureConnectionCached === null) {
			const url = `https://${this.getControlHost()}`;
			const data = {
				method: "login",
				params: {
					encrypt_type: "3",
					username: this.user,
				},
			};

			try {
				const res = await this.request("POST", url, this.headers, data);

				const response = res.data;

				this.isSecureConnectionCached =
					"error_code" in response &&
					response.error_code === -40413 &&
					"result" in response &&
					"data" in response.result &&
					"encrypt_type" in response.result.data &&
					response.result.data.encrypt_type.includes("3");
			} catch (error) {
				console.error("Error checking secure connection:", error);
				this.isSecureConnectionCached = false;
			}
		}

		return this.isSecureConnectionCached || false;
	}

	private getHashedPassword(): string {
		if (this.passwordEncryptionMethod === EncryptionMethod.MD5) {
			return this.hashedPassword;
		} else if (this.passwordEncryptionMethod === EncryptionMethod.SHA256) {
			return this.hashedSha256Password;
		} else {
			throw new Error("Failure detecting hashing algorithm.");
		}
	}

	private validateDeviceConfirm(nonce: string, deviceConfirm: string): boolean {
		this.passwordEncryptionMethod = null;

		const hashedNoncesWithSHA256 = this.sha256HexUpper(
			this.cnonce + this.hashedSha256Password + nonce
		);

		const hashedNoncesWithMD5 = this.sha256HexUpper(
			this.cnonce + this.hashedPassword + nonce
		);

		if (deviceConfirm === hashedNoncesWithSHA256 + nonce + this.cnonce) {
			this.passwordEncryptionMethod = EncryptionMethod.SHA256;
		} else if (deviceConfirm === hashedNoncesWithMD5 + nonce + this.cnonce) {
			this.passwordEncryptionMethod = EncryptionMethod.MD5;
		}

		return this.passwordEncryptionMethod !== null;
	}

	private generateEncryptionToken(tokenType: string, nonce: string): Buffer {
		const hashedKey = this.sha256HexUpper(
			this.cnonce + this.getHashedPassword() + nonce
		);

		const fullHash = CryptoJS.SHA256(
			CryptoJS.enc.Utf8.parse(tokenType + this.cnonce + nonce + hashedKey)
		);

		const hashHex = fullHash.toString(CryptoJS.enc.Hex);
		const hashBuffer = Buffer.from(hashHex, "hex");
		return hashBuffer.subarray(0, 16);
	}

	private async generateNonce(length: number): Promise<Buffer> {
		const randomBytes = await Random.getRandomBytesAsync(length);
		return Buffer.from(randomBytes);
	}

	private async refreshStok(loginRetryCount = 0): Promise<string> {
		this.debugLog("Refreshing stok...");
		this.cnonce = (await this.generateNonce(8)).toString("hex").toUpperCase();
		const url = `https://${this.getControlHost()}`;

		let data: any;

		if (await this.isSecureConnection()) {
			this.debugLog("Connection is secure.");
			data = {
				method: "login",
				params: {
					cnonce: this.cnonce,
					encrypt_type: "3",
					username: this.user,
				},
			};
		} else {
			this.debugLog("Connection is insecure.");
			data = {
				method: "login",
				params: {
					hashed: true,
					password: this.hashedPassword,
					username: this.user,
				},
			};
		}

		let res: FetchBlobResponse | undefined = undefined;
		try {
			res = await this.request("POST", url, this.headers, data);
		} catch (err) {
			console.error("ERROR", (err as Error).message);
		}

		if (!res) return Promise.resolve("");
		this.debugLog("Status code: " + res.info().status);

		const result: LoginResponse = res.json();
		if (res.info().status === 401) {
			try {
				if (result.result?.data?.code === -40411) {
					this.debugLog("Code is -40411, raising Exception.");
					throw new Error("Invalid authentication data");
				}
			} catch (e: any) {
				if (e.message === "Invalid authentication data") throw e;
			}
		}

		let responseData = res.data;

		if (await this.isSecureConnection()) {
			this.debugLog("Processing secure response.");
			const resultData = responseData?.result?.data;
			if (resultData?.nonce && resultData?.device_confirm) {
				this.debugLog("Validating device confirm.");
				const nonce = resultData.nonce;
				if (this.validateDeviceConfirm(nonce, resultData.device_confirm)) {
					this.debugLog("Signing in with digestPasswd.");
					const digestPasswd = this.sha256HexUpper(
						this.getHashedPassword() + this.cnonce + nonce
					);

					const digest = digestPasswd + this.cnonce + nonce;

					data = {
						method: "login",
						params: {
							cnonce: this.cnonce,
							encrypt_type: "3",
							digest_passwd: digest,
							username: this.user,
						},
					};

					res = await this.request("POST", url, this.headers, data);

					if (!res) return Promise.resolve("");

					responseData = res.data;
					const result = responseData.result;

					if (result?.start_seq) {
						if (result.user_group && result.user_group !== "root") {
							this.debugLog(
								"Incorrect user_group detected, raising Exception."
							);
							throw new Error("Invalid authentication data");
						}
						this.debugLog("Generating encryption tokens.");
						this.lsk = this.generateEncryptionToken("lsk", nonce);
						this.ivb = this.generateEncryptionToken("ivb", nonce);
						this.seq = result.start_seq;
					}
				} else {
					if (
						this.retryStok &&
						responseData.error_code === -40413 &&
						loginRetryCount < MAX_LOGIN_RETRIES
					) {
						loginRetryCount++;
						this.debugLog(
							`Incorrect device_confirm value, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`
						);
						return this.refreshStok(loginRetryCount);
					} else {
						this.debugLog("Incorrect device_confirm value, raising Exception.");
						throw new Error("Invalid authentication data");
					}
				}
			}
		} else {
			this.passwordEncryptionMethod = "MD5";
		}

		const dataField: any = responseData?.result?.data || responseData?.data;

		if (
			dataField?.sec_left &&
			dataField.sec_left > 0 &&
			(dataField?.time || dataField?.max_time || dataField?.code === -40404)
		) {
			throw new Error(
				`Temporary Suspension: Try again in ${dataField.sec_left} seconds`
			);
		}

		if (responseData.result?.stok) {
			this.debugLog("Saving stok.");
			this.stok = responseData.result!.stok!;
			return this.stok || "";
		}

		if (
			this.retryStok &&
			responseData.error_code === -40413 &&
			loginRetryCount < MAX_LOGIN_RETRIES
		) {
			loginRetryCount++;
			this.debugLog(
				`Unexpected response, retrying: ${loginRetryCount}/${MAX_LOGIN_RETRIES}.`
			);
			return this.refreshStok(loginRetryCount);
		} else {
			this.debugLog("Unexpected response, raising Exception.");
			throw new Error("Invalid authentication data");
		}
	}

	private async ensureAuthenticated(): Promise<void> {
		if (!this.stok) {
			await this.refreshStok();
		}
	}

	async getLED(): Promise<TapoLED> {
		const result = await this.executeFunction<TapoLEDConfig>("getLedStatus", {
			led: { name: ["config"] },
		});
		console.log(result);

		return result.led.config;
	}

	public async getTime(): Promise<TapoTimeData> {
		return await this.executeFunction<TapoTimeData>("getClockStatus", {
			system: { name: "clock_status" },
		});
	}

	public async getTimeCorrection(): Promise<number | undefined> {
		if (this.timeCorrection === undefined) {
			const currentTime = await this.getTime();
			const nowTS = Math.floor(Date.now() / 1000);
			const timeReturned =
				currentTime?.system?.clock_status?.seconds_from_1970 !== undefined;

			if (timeReturned) {
				this.timeCorrection =
					nowTS - currentTime.system.clock_status.seconds_from_1970;
			} else if (currentTime?.timestamp !== undefined) {
				this.timeCorrection = nowTS - currentTime.timestamp;
			}
		}

		return this.timeCorrection;
	}

	public async getEvents(
		startTime: number | false = false,
		endTime: number | false = false
	): Promise<any[]> {
		const timeCorrection = await this.getTimeCorrection();
		if (timeCorrection === undefined) {
			throw new Error("Failed to get correct camera time.");
		}

		const nowTS = Date.now() / 1000;
		if (startTime === false) {
			startTime = nowTS - timeCorrection - 10 * 60;
		}
		if (endTime === false) {
			endTime = nowTS + -timeCorrection + 60;
		}

		try {
			const responseData = await this.executeFunction<any>(
				"searchDetectionList",
				{
					playback: {
						search_detection_list: {
							start_index: 0,
							channel: 0,
							start_time: startTime * 1000,
							end_time: endTime * 1000,
							end_index: 999,
						},
					},
				}
			);

			const events: any[] = [];

			const detectionsReturned =
				responseData?.playback?.search_detection_list !== undefined;

			if (detectionsReturned) {
				for (const event of responseData.playback.search_detection_list) {
					event.start_time += timeCorrection;
					event.end_time += timeCorrection;
					event.startRelative = nowTS - event.start_time;
					event.endRelative = nowTS - event.end_time;
					events.push(event);
				}
			}

			console.log("events", events);
			return events;
		} catch (error) {
			return [];
		}
	}

	public async getVideoQualities(): Promise<TapoVideoQualities> {
		return this.executeFunction<TapoVideoQualities>("getVideoQualities", {
			video: { name: ["main"] },
		});
	}

	public async getVideoCapability(): Promise<TapoVideoCapabilities> {
		return this.executeFunction<TapoVideoCapabilities>("getVideoCapability", {
			video_capability: { name: ["main"] },
		});
	}

	public async getPrivacyMode(): Promise<TapoLensMaskStatus> {
		const data = await this.executeFunction<TapoLensMask>("getLensMaskConfig", {
			lens_mask: { name: ["lens_mask_info"] },
		});
		return data.lens_mask.lens_mask_info.enabled;
	}

	public async getMediaEncrypt(): Promise<TapoMediaEncryptStatus> {
		const data = await this.executeFunction<TapoMediaEncrypt>(
			"getMediaEncrypt",
			{
				cet: { name: ["media_encrypt"] },
			}
		);
		return data.cet.media_encrypt.enabled;
	}

	public async getTimezone(): Promise<TapoTimezone> {
		const data = await this.executeFunction<TapoTimezoneData>("getTimezone", {
			system: { name: ["basic"] },
		});
		return data.system.basic;
	}

	/**
	 * Set the timezone for the camera.
	 * @param timezone The timezone string (e.g., "UTC+01:00").
	 * @param zoneID The zone ID (e.g., "Europe/Brussels").
	 * @param timingMode The timing mode (e.g., "ntd").
	 * @returns A promise that resolves to the updated TapoTimezone object.
	 */
	public async setTimezone(
		timezone: string,
		zoneID: string,
		timingMode: string
	): Promise<TapoTimezone> {
		const data = await this.executeFunction<TapoTimezoneData>("setTimezone", {
			system: {
				basic: {
					timing_mode: timingMode,
					timezone: timezone,
					zone_id: zoneID,
				},
			},
		});
		return data.system.basic;
	}

	public async getRotationStatus(): Promise<TapoRotationStatus> {
		const data = await this.executeFunction<TapoRotationStatusData>(
			"getRotationStatus",
			{
				image: { name: ["switch"] },
			}
		);
		return data.image.switch;
	}

	public async getSDCard(): Promise<Record<string, TapoSDCardInfo>[]> {
		const data = await this.executeFunction<TapoSDCardData>("getSdCardStatus", {
			harddisk_manage: { table: ["hd_info"] },
		});
		return data.harddisk_manage.hd_info;
	}

	public async setPrivacyMode(enabled: TapoLensMaskStatus): Promise<void> {
		return await this.executeFunction<void>("setLensMaskConfig", {
			lens_mask: { lens_mask_info: { enabled: enabled } },
		});
	}

	public async moveMotor(x: number, y: number): Promise<void> {
		return await this.performRequest({
			method: "do",
			motor: { move: { x_coord: `${x}`, y_coord: `${y}` } },
		});
	}

	public async moveMotorStep(angle: number): Promise<void> {
		if (angle < 0 || angle >= 360) {
			throw new Error("Angle must be in a range 0 <= angle < 360");
		}
		return await this.performRequest({
			method: "do",
			motor: { movestep: { direction: `${angle}` } },
		});
	}

	public async moveMotorClockWise(): Promise<void> {
		return this.moveMotorStep(0);
	}

	public async moveMotorCounterClockWise(): Promise<void> {
		return this.moveMotorStep(180);
	}

	public async moveMotorVertical(): Promise<void> {
		return this.moveMotorStep(90);
	}

	public async moveMotorHorizontal(): Promise<void> {
		return this.moveMotorStep(270);
	}

	public async setLEDEnabled(enabled: TapoLEDStatus): Promise<void> {
		return await this.executeFunction<void>("setLedStatus", {
			led: { config: { enabled: enabled } },
		});
	}
}
