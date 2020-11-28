import * as stream from 'stream';

import chai from 'chai';

import Body from '../src/body.js';
import {FetchError} from '../src/errors/fetch-error.js';

const {expect} = chai;

describe('Body', () => {
	function buildSimpleReadableStream() {
		const theStream = new stream.Readable();
		theStream._read = () => {};
		return theStream;
	}

	it('should accept a string', () => {
		const body = new Body('thebody');
		expect(body.body).to.be.an.instanceof(Buffer);
	});

	it('should handle emitted errors', () => {
		const theStream = buildSimpleReadableStream();
		const body = new Body(theStream);

		// Simulate an error from the stream
		theStream.emit('error', new Error('boom'));

		return body.buffer().then(() => {
			expect.fail('should not have resolved');
		}, error => {
			expect(error).to.be.an.instanceOf(FetchError);
		});
	});

	it('should handle a premature closure', () => {
		const theStream = buildSimpleReadableStream();
		const body = new Body(theStream);

		// Simulate a premature closure of the stream
		theStream.destroy();

		return body.buffer().then(() => {
			expect.fail('should not have resolved');
		}, error => {
			expect(error).to.be.an.instanceOf(FetchError);
		});
	});
});
